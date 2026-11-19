import argparse
import asyncio
import json
import shutil
import signal
import sys
import tempfile
from pathlib import Path

from . import __version__
from .analysis import clean
from .config import Config
from .engine import Engine
from .export import export_report
from .store import Store


def parser():
    root = argparse.ArgumentParser(prog="raven", description="RAVEN — terminal reconnaissance workbench")
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create a workspace and explicit scope")
    init.add_argument("directory", type=Path)
    init.add_argument("-d", "--domain", action="append", required=True)
    init.add_argument("--name")
    init.add_argument("--include", action="append", default=[], help="Extra host or wildcard rule; quote *.domain")
    init.add_argument("--exclude", action="append", default=[])
    sub.add_parser("demo", help="Open an isolated offline TUI with synthetic observations")
    sub.add_parser("doctor", help="Check Python and optional connectors; no network")
    for name, help_ in [("tui", "Open interactive dashboard"), ("scan", "Collect passive data; optionally probe HTTP roots"),
                        ("import", "Import domains, URLs or httpx JSONL"), ("js", "Analyze saved JavaScript"),
                        ("export", "Write JSON, Markdown and text reports"), ("list", "Show stored results")]:
        cmd = sub.add_parser(name, help=help_)
        cmd.add_argument("-w", "--workspace", type=Path, required=True)
        if name == "scan":
            cmd.add_argument("--probe", action="store_true", help="Send HTTP GET requests to discovered web roots")
            cmd.add_argument("--js", action="store_true", help="Read linked in-scope JS (requires --probe)")
            cmd.add_argument("--http-only", action="store_true", help="Probe stored hosts without passive collectors")
        if name in ("import", "js"):
            cmd.add_argument("file", type=Path)
        if name == "js":
            cmd.add_argument("--base", required=True, help="In-scope document URL for resolving relative paths")
        if name == "export":
            cmd.add_argument("--output", type=Path)
        if name == "list":
            cmd.add_argument("kind", choices=["hosts", "urls", "changes", "runs"])
            cmd.add_argument("--json", action="store_true")
    return root


async def scan(engine, args):
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, engine.stop.set)
    loop.add_signal_handler(signal.SIGTERM, engine.stop.set)
    try:
        return await engine.run(not args.http_only, args.probe or args.http_only, args.js)
    finally:
        loop.remove_signal_handler(signal.SIGINT)
        loop.remove_signal_handler(signal.SIGTERM)


def main():
    args = parser().parse_args()
    try:
        if args.command == "init":
            config = Config(args.name or args.domain[0], args.domain, list(dict.fromkeys(args.domain + args.include)), args.exclude)
            config.save(args.directory.expanduser())
            print(f"Workspace created: {args.directory}\nEdit scope.json to adjust rules and limits.")
            return
        if args.command == "doctor":
            from importlib.metadata import version
            print(f"Python {sys.version.split()[0]} · RAVEN {__version__}")
            for package in ("textual", "aiohttp"):
                print(f"{package}: {version(package)}")
            for tool in ("subfinder", "gau"):
                print(f"{tool}: {shutil.which(tool) or 'optional / not installed'}")
            return
        if args.command == "demo":
            from .demo import seed_demo
            from .tui import RavenApp
            with tempfile.TemporaryDirectory(prefix="raven-demo-") as directory:
                workspace = Path(directory)
                seed_demo(workspace)
                RavenApp(workspace, demo=True).run()
            return
        workspace = args.workspace.expanduser().resolve()
        config = Config.load(workspace)
        if args.command == "tui":
            from .tui import RavenApp
            RavenApp(workspace).run()
            return
        store = Store(workspace)
        try:
            def emit(event):
                if event["kind"] == "log":
                    print(clean(event["text"], 1000), file=sys.stderr, flush=True)
            engine = Engine(config, store, emit)
            if args.command == "scan":
                asyncio.run(scan(engine, args))
                latest = store.runs()[0]
                if latest["state"] != "complete":
                    raise SystemExit(2)
            elif args.command in ("import", "js"):
                engine.import_file(args.file.expanduser(), getattr(args, "base", None))
            elif args.command == "export":
                print(export_report(store, config, args.output.expanduser() if args.output else None))
            elif args.command == "list":
                if args.kind == "hosts":
                    records = [a for a in store.assets() if config.scope.allows_host(a["host"])]
                elif args.kind == "urls":
                    records = [u for u in store.urls() if config.scope.allows_url(u["url"])]
                elif args.kind == "changes":
                    records = [c for c in store.changes() if (config.scope.allows_url(c["value"]) if "://" in c["value"] else config.scope.allows_host(c["value"]))]
                else:
                    records = store.runs()
                if args.json:
                    print(json.dumps(records, indent=2, ensure_ascii=False))
                else:
                    for record in records:
                        print(clean(record.get("host") or record.get("url") or json.dumps(record, ensure_ascii=False), 10000))
        finally:
            store.close()
    except FileExistsError:
        print("ERROR: scope.json already exists; use a new workspace or edit the existing scope explicitly.", file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, TypeError) as exc:
        print("ERROR: " + clean(exc), file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("Interrupted; previously committed results are retained.", file=sys.stderr)
        raise SystemExit(130)

