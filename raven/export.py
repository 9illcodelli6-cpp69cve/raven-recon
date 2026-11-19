import json
from datetime import datetime, timezone
from pathlib import Path

from .analysis import clean


def export_report(store, config, directory: Path | None = None):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = directory or store.workspace / "exports" / stamp
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    assets = [a for a in store.assets() if config.scope.allows_host(a["host"])]
    urls = [u for u in store.urls() if config.scope.allows_url(u["url"])]
    changes = [c for c in store.changes(100000) if (
        config.scope.allows_url(c["value"]) if "://" in c["value"] else config.scope.allows_host(c["value"])
    )]
    report = {"tool": "RAVEN 0.1.0", "project": config.name, "generated_at": stamp,
              "scope": {"include": config.include, "exclude": config.exclude, "ports": config.ports},
              "notice": "Priority scores are triage hints, not confirmed vulnerabilities. HTTP data is the latest stored observation.",
              "assets": assets, "urls": urls, "changes": changes, "runs": store.runs()}
    (directory / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (directory / "hosts.txt").write_text("".join(a["host"] + "\n" for a in assets), encoding="utf-8")
    (directory / "urls.txt").write_text("".join(u["url"] + "\n" for u in urls), encoding="utf-8")

    def cell(value):
        return clean(value, 300).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("`", "\\`")

    lines = [f"# RAVEN — {cell(config.name)}", "", report["notice"], "",
             f"Assets: {len(assets)} · URLs: {len(urls)} · URL families: {len(set(u['family'] for u in urls))}", "",
             "## Latest stored HTTP observations", "", "| Score | Host | Status | Title | Signals |",
             "|---:|---|---:|---|---|"]
    for a in assets:
        probe = a["probe"]
        lines.append("| " + " | ".join(map(cell, [a["score"], a["host"], probe.get("status") or "—",
                      probe.get("title", ""), ", ".join(a["reasons"])])) + " |")
    lines += ["", "## Recent changes", "", "| Run | Change | Asset | Detail |", "|---:|---|---|---|"]
    for c in changes[:300]:
        lines.append("| " + " | ".join(map(cell, [c["run_id"], c["kind"], c["value"], c["detail"]])) + " |")
    lines += ["", "Full URLs, provenance, evidence, and run history are in report.json.",
              "Missing from a later passive collection does not imply removed/offline.", ""]
    (directory / "report.md").write_text("\n".join(lines), encoding="utf-8")
    for path in directory.iterdir():
        if path.is_file():
            path.chmod(0o600)
    return directory

