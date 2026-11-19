import asyncio
import json
import shutil
from pathlib import Path

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Footer, Input, Label, ProgressBar, RichLog, Static, TabbedContent, TabPane

from .analysis import clean
from .config import Config
from .engine import Engine
from .export import export_report
from .store import Store


def literal(value, style=""):
    return Text(clean(value, 2000), style=style)


class Details(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close")]

    def __init__(self, record):
        super().__init__()
        self.record = record

    def compose(self):
        with Vertical(id="detail-dialog"):
            yield Label("OBSERVATION / EVIDENCE", classes="dialog-title")
            with VerticalScroll():
                yield Static(Text(json.dumps(self.record, indent=2, ensure_ascii=False)))
            yield Button("Close  [Esc]", id="close-detail", variant="primary")

    @on(Button.Pressed, "#close-detail")
    def close_detail(self):
        self.dismiss()

    def action_dismiss(self):
        self.dismiss()


class FileImport(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Cancel")]

    def __init__(self, default_base):
        super().__init__()
        self.default_base = default_base

    def compose(self):
        with Vertical(id="import-dialog"):
            yield Label("IMPORT LOCAL EVIDENCE", classes="dialog-title")
            yield Label("Domains / URLs / httpx JSONL / saved JavaScript")
            yield Input(placeholder="/home/kali/recon/hosts.txt", id="file-path")
            yield Checkbox("Analyze as JavaScript", id="js-import")
            yield Input(value=self.default_base, placeholder="Page URL used to resolve relative JS paths", id="js-base")
            yield Static("For JS, set the document URL where the script executes.", classes="muted")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Import", id="do-import", variant="primary")
                yield Button("Cancel", id="cancel-import")

    @on(Button.Pressed, "#do-import")
    def apply(self):
        path = self.query_one("#file-path", Input).value.strip()
        if not path:
            self.notify("Enter a file path", severity="warning")
            return
        base = self.query_one("#js-base", Input).value if self.query_one("#js-import", Checkbox).value else None
        self.dismiss((path, base))

    @on(Button.Pressed, "#cancel-import")
    def cancel(self):
        self.dismiss()

    def action_dismiss(self):
        self.dismiss()


class RavenApp(App):
    TITLE = "RAVEN / Recon Workbench"
    CSS_PATH = "theme.tcss"
    BINDINGS = [
        Binding("ctrl+r", "run", "Run"), Binding("ctrl+s", "stop", "Stop"),
        Binding("ctrl+f", "search", "Filter"), Binding("ctrl+i", "import", "Import"),
        Binding("ctrl+e", "export", "Export"), Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self, workspace: Path, demo=False):
        super().__init__()
        self.workspace = workspace
        self.config = Config.load(workspace)
        self.store = Store(workspace)
        self.demo = demo
        self.engine = None
        self.scan_task = None
        self.records = {}
        self.dirty = True
        self.filter_text = ""

    def compose(self) -> ComposeResult:
        with Horizontal(id="topbar"):
            yield Static("RAVEN", id="brand")
            yield Static(literal(self.config.name), id="project-name")
            yield Static("OFFLINE DEMO" if self.demo else "READY", id="run-state")
        with Horizontal(id="body"):
            with VerticalScroll(id="sidebar"):
                yield Static("RECON WORKBENCH", classes="section")
                yield Static("SURFACE\nINTELLIGENCE", id="tagline")
                yield Static("COLLECTION", classes="section")
                yield Checkbox("Passive sources", value=True, id="passive")
                yield Checkbox("HTTP roots", id="probe")
                yield Checkbox("Read linked JS", id="javascript")
                yield Button("Run collection", id="run", variant="primary")
                yield Button("Stop", id="stop", disabled=True)
                yield Static("WORKSPACE", classes="section")
                yield Button("Import file", id="import")
                yield Button("Export report", id="export")
                yield Button("Scope & limits", id="scope")
                yield Static("CONNECTORS", classes="section")
                for name in ("subfinder", "gau"):
                    present = shutil.which(name) is not None
                    yield Static(Text(("● " if present else "○ ") + name + (" / ready" if present else " / optional"), style="#60e5cf" if present else "#8290a8"))
                yield Static(f"{self.config.rate:g} req/s · {self.config.concurrency} workers\n{self.config.max_requests} request budget", id="limits")
            with Vertical(id="main"):
                with Horizontal(id="metrics"):
                    yield Static(id="assets-stat", classes="metric")
                    yield Static(id="http-stat", classes="metric")
                    yield Static(id="urls-stat", classes="metric")
                    yield Static(id="families-stat", classes="metric")
                yield Input(placeholder="Filter hosts, URLs, status, sources or signals…  Ctrl+F", id="search")
                with TabbedContent(id="tabs"):
                    with TabPane("Surface", id="surface-pane"):
                        yield DataTable(id="surface", cursor_type="row", zebra_stripes=True)
                    with TabPane("Endpoints", id="endpoints-pane"):
                        yield DataTable(id="endpoints", cursor_type="row", zebra_stripes=True)
                    with TabPane("Changes", id="changes-pane"):
                        yield DataTable(id="changes", cursor_type="row", zebra_stripes=True)
                    with TabPane("Runs", id="runs-pane"):
                        yield DataTable(id="runs", cursor_type="row", zebra_stripes=True)
                yield Static("Enter a row for evidence · Scores indicate review priority", id="table-hint")
                yield ProgressBar(total=100, show_eta=False, id="progress")
                yield RichLog(id="events", max_lines=300, markup=False, wrap=True, highlight=False)
        yield Footer()

    def on_mount(self):
        self.query_one("#surface", DataTable).add_columns("Score", "Host", "HTTP", "Title", "Server", "Signals")
        self.query_one("#endpoints", DataTable).add_columns("Score", "URL", "Family", "Source")
        self.query_one("#changes", DataTable).add_columns("Run", "Change", "Asset / URL", "Detail")
        self.query_one("#runs", DataTable).add_columns("Run", "Started UTC", "Mode", "State", "Note")
        self.refresh_data()
        self.set_interval(1.0, self.tick)
        self.query_one("#surface", DataTable).focus()
        if self.demo:
            self.query_one("#progress", ProgressBar).update(total=100, progress=100)
        self.log_event("OFFLINE DEMO · Synthetic data · Network actions disabled" if self.demo else "Ready · Select collection stages or import saved recon output")
        self.log_event("HTTP collection requests web roots; discovered endpoints are saved for review.")

    def tick(self):
        if self.dirty and len(self.screen_stack) == 1:
            self.refresh_data()

    def log_event(self, text):
        from datetime import datetime
        stamp = datetime.now().strftime("%H:%M:%S")
        self.query_one("#events", RichLog).write(Text(stamp + "  " + clean(text, 1000)))

    def event(self, event):
        self.dirty = True
        if event["kind"] == "log":
            self.log_event(event["text"])
        elif event["kind"] == "progress":
            self.query_one("#progress", ProgressBar).update(total=max(1, event["total"]), progress=event["done"])
            self.query_one("#run-state", Static).update(f"RUNNING / {event['requests']} req")

    def refresh_data(self):
        self.dirty = False
        assets = [a for a in self.store.assets() if self.config.scope.allows_host(a["host"])]
        urls = [u for u in self.store.urls() if self.config.scope.allows_url(u["url"])]
        changes = [c for c in self.store.changes() if (
            self.config.scope.allows_url(c["value"]) if "://" in c["value"] else self.config.scope.allows_host(c["value"])
        )]
        observed = sum(a["probe"].get("status") is not None for a in assets)
        for id_, number, label in (("assets", len(assets), "ASSETS"), ("http", observed, "HTTP OBSERVED"),
                                   ("urls", len(urls), "URLS"), ("families", len({u["family"] for u in urls}), "URL FAMILIES")):
            self.query_one(f"#{id_}-stat", Static).update(f"[bold #edf6ff]{number:,}[/]\n[#8290a8]{label}[/]")
        data = {"surface": assets, "endpoints": urls, "changes": changes, "runs": self.store.runs()}
        self.records = {}
        for kind, records in data.items():
            table = self.query_one("#" + kind, DataTable)
            position = table.cursor_row
            table.clear()
            records = [r for r in records if self.filter_text in json.dumps(r, ensure_ascii=False).lower()]
            for index, row in enumerate(records[:1000]):
                key = kind + ":" + str(index)
                self.records[key] = row
                if kind == "surface":
                    p = row["probe"]
                    status = p.get("status")
                    tone = "#60e5cf" if status and status < 400 else ("#f3bb77" if status else "#8290a8")
                    cells = [literal(row["score"], "bold #b39aff"), literal(row["host"]),
                             literal(status or ("ERR" if p else "—"), tone), literal(p.get("title", "")[:48]),
                             literal(p.get("server", "")[:20]), literal(", ".join(row["reasons"]))]
                elif kind == "endpoints":
                    cells = [literal(row["score"], "bold #b39aff"), literal(row["url"]), literal(row["family"]), literal(", ".join(row["sources"]))]
                elif kind == "changes":
                    cells = [literal(row["run_id"]), literal(row["kind"], "#60e5cf"), literal(row["value"]), literal(row["detail"])]
                else:
                    cells = [literal(row["id"]), literal(row["started"]), literal(row["mode"]), literal(row["state"]), literal(row["note"])]
                table.add_row(*cells, key=key)
            if table.row_count:
                table.move_cursor(row=min(position, table.row_count - 1), animate=False, scroll=False)
        self.query_one("#table-hint", Static).update("Enter: evidence · Priority ≠ vulnerability · Up to 1,000 matching rows/tab; exports include all")

    @on(Input.Changed, "#search")
    def filter_changed(self, event):
        self.filter_text = event.value.strip().lower()
        self.dirty = True
        self.refresh_data()

    @on(DataTable.RowSelected)
    def selected(self, event):
        row = self.records.get(event.row_key.value)
        if row:
            self.push_screen(Details(row))

    @on(Button.Pressed)
    def clicked(self, event):
        actions = {"run": self.action_run, "stop": self.action_stop, "import": self.action_import,
                   "export": self.action_export, "scope": self.show_scope}
        if event.button.id in actions:
            actions[event.button.id]()

    def busy(self):
        return self.scan_task is not None and not self.scan_task.done()

    def action_run(self):
        if self.demo:
            self.notify("Demo is offline. Create a workspace with raven init to collect real data.")
            return
        if self.busy():
            self.notify("A collection is already running")
            return
        passive = self.query_one("#passive", Checkbox).value
        probe = self.query_one("#probe", Checkbox).value
        js = self.query_one("#javascript", Checkbox).value
        if (js and not probe) or not (passive or probe):
            self.notify("Select a stage. Reading JS requires HTTP roots.", severity="warning")
            return
        try:
            self.config = Config.load(self.workspace)
        except (OSError, ValueError, TypeError) as exc:
            self.notify(clean(exc), severity="error")
            return
        self.engine = Engine(self.config, self.store, self.event)
        self.scan_task = asyncio.create_task(self.perform_run(passive, probe, js))

    async def perform_run(self, passive, probe, javascript):
        self.query_one("#run", Button).disabled = True
        self.query_one("#stop", Button).disabled = False
        self.query_one("#run-state", Static).update("RUNNING")
        self.query_one("#progress", ProgressBar).update(total=100, progress=0)
        try:
            await self.engine.run(passive, probe, javascript)
        except Exception as exc:
            self.log_event("ERROR  " + clean(exc))
            self.notify(clean(exc), severity="error")
        finally:
            self.query_one("#run", Button).disabled = False
            self.query_one("#stop", Button).disabled = True
            self.query_one("#run-state", Static).update("READY")
            self.query_one("#progress", ProgressBar).update(total=100, progress=100)
            self.dirty = True

    def action_stop(self):
        if self.engine and self.busy():
            self.engine.stop.set()
            self.log_event("Stopping new work; waiting for in-flight requests to finish")

    def action_search(self):
        self.query_one("#search", Input).focus()

    def action_import(self):
        if self.busy():
            self.notify("Stop or finish the current collection first")
            return
        from .scope import origin
        self.push_screen(FileImport(origin(self.config.roots[0])), self.import_result)

    def import_result(self, result):
        if not result:
            return
        try:
            self.config = Config.load(self.workspace)
            engine = Engine(self.config, self.store, self.event)
            engine.import_file(Path(result[0]).expanduser(), result[1])
            self.refresh_data()
        except (OSError, ValueError, TypeError) as exc:
            self.notify(clean(exc), severity="error")

    def action_export(self):
        try:
            directory = export_report(self.store, self.config)
            self.log_event("Export saved: " + str(directory))
            self.notify("Report JSON + Markdown + host/URL lists exported")
        except OSError as exc:
            self.notify(clean(exc), severity="error")

    def show_scope(self):
        self.push_screen(Details({"include": self.config.include, "exclude": self.config.exclude,
            "ports": self.config.ports, "rate": self.config.rate, "concurrency": self.config.concurrency,
            "max_hosts": self.config.max_hosts, "max_requests": self.config.max_requests,
            "workspace": str(self.workspace), "edit": "Edit scope.json; collection reloads it before each run."}))

    async def action_quit(self):
        if self.busy():
            self.action_stop()
            await self.scan_task
        self.exit()

    async def on_unmount(self):
        if self.busy():
            self.action_stop()
            await self.scan_task
        self.store.close()
