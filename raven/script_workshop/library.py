"""RAVEN Phase III — Script Workshop library.

Provides reusable, pre-approved building blocks for common script tasks.
All library functions are parameterized and safe within their declared profile.

CRITICAL:
  Library functions are helpers for PURE_LOCAL and LOCAL_FIXTURE profiles only
  unless explicitly noted otherwise.
  No raw sockets, no shell injection, no credential harvesting.
  Security authority: NONE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class LibraryBlock:
    """A reusable, pre-reviewed code building block."""
    block_id: str
    name: str
    description: str
    code_template: str
    profile_requirement: str  # minimum ExecutionProfile value
    parameters: list[str] = field(default_factory=list)
    example_usage: str = ""


# ── Library registry ──────────────────────────────────────────────────────────

LIBRARY_BLOCKS: list[LibraryBlock] = [
    LibraryBlock(
        block_id="lb_json_load",
        name="Load JSON Fixture",
        description="Load a JSON fixture file from the workspace fixtures directory",
        code_template="""
import json
import pathlib

def load_fixture(fixture_name: str) -> dict:
    path = pathlib.Path("fixtures") / fixture_name
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
""".strip(),
        profile_requirement="LOCAL_FIXTURE",
        parameters=["fixture_name"],
        example_usage='data = load_fixture("network_observations.json")',
    ),

    LibraryBlock(
        block_id="lb_csv_reader",
        name="Read CSV Data",
        description="Read a CSV file from the workspace fixtures directory",
        code_template="""
import csv
import pathlib

def read_csv(filename: str) -> list[dict]:
    path = pathlib.Path("fixtures") / filename
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))
""".strip(),
        profile_requirement="LOCAL_FIXTURE",
        parameters=["filename"],
        example_usage='rows = read_csv("scan_results.csv")',
    ),

    LibraryBlock(
        block_id="lb_count_by_field",
        name="Count By Field",
        description="Count occurrences of each value for a given field in a list of records",
        code_template="""
from collections import Counter
from typing import Any

def count_by_field(records: list[dict], field: str) -> dict[str, int]:
    return dict(Counter(r.get(field, "MISSING") for r in records))
""".strip(),
        profile_requirement="PURE_LOCAL",
        parameters=["records", "field"],
        example_usage='counts = count_by_field(rows, "status_code")',
    ),

    LibraryBlock(
        block_id="lb_filter_records",
        name="Filter Records",
        description="Filter a list of records by field value",
        code_template="""
def filter_records(records: list[dict], field: str, value: Any) -> list[dict]:
    return [r for r in records if r.get(field) == value]
""".strip(),
        profile_requirement="PURE_LOCAL",
        parameters=["records", "field", "value"],
        example_usage='denied = filter_records(rows, "status", "DENIED")',
    ),

    LibraryBlock(
        block_id="lb_summarize_access_tuples",
        name="Summarize Access Tuples",
        description=(
            "Produce a frequency summary of access control scenarios "
            "grouped by principal type and decision"
        ),
        code_template="""
from collections import defaultdict

def summarize_access_decisions(tuples: list[dict]) -> dict:
    summary = defaultdict(lambda: {"ALLOWED": 0, "DENIED": 0, "UNKNOWN": 0})
    for t in tuples:
        ptype = t.get("principal_type", "UNKNOWN")
        decision = t.get("observed_decision", "UNKNOWN")
        summary[ptype][decision] = summary[ptype].get(decision, 0) + 1
    return dict(summary)
""".strip(),
        profile_requirement="PURE_LOCAL",
        parameters=["tuples"],
        example_usage='summary = summarize_access_decisions(fixture_data)',
    ),

    LibraryBlock(
        block_id="lb_deduplicate",
        name="Deduplicate Records",
        description="Remove duplicate records from a list based on a key field",
        code_template="""
def deduplicate(records: list[dict], key_field: str) -> list[dict]:
    seen: set = set()
    result: list[dict] = []
    for r in records:
        k = r.get(key_field)
        if k not in seen:
            seen.add(k)
            result.append(r)
    return result
""".strip(),
        profile_requirement="PURE_LOCAL",
        parameters=["records", "key_field"],
        example_usage='unique = deduplicate(rows, "finding_id")',
    ),

    LibraryBlock(
        block_id="lb_safe_http_get",
        name="Safe HTTP GET (Public Research)",
        description=(
            "Perform a safe, read-only HTTP GET request for public technical "
            "research. Only for PUBLIC_RESEARCH_READONLY profile. "
            "Returns response text and status code."
        ),
        code_template="""
import urllib.request
import urllib.error
from typing import Optional

def safe_http_get(url: str, timeout: int = 10) -> tuple[int, str]:
    \"\"\"Safe, read-only HTTP GET. Only for public research URLs.\"\"\"
    req = urllib.request.Request(url, headers={"User-Agent": "RAVEN/research"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, str(e.reason)
    except urllib.error.URLError as e:
        return 0, str(e.reason)
""".strip(),
        profile_requirement="PUBLIC_RESEARCH_READONLY",
        parameters=["url", "timeout"],
        example_usage='status, body = safe_http_get("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")',
    ),
]

# Index by block_id for fast lookup
_BLOCK_INDEX: dict[str, LibraryBlock] = {b.block_id: b for b in LIBRARY_BLOCKS}


def get_block(block_id: str) -> Optional[LibraryBlock]:
    return _BLOCK_INDEX.get(block_id)


def list_blocks_for_profile(profile_value: str) -> list[LibraryBlock]:
    """List all library blocks compatible with a given profile (or lower)."""
    profile_order = [
        "PURE_LOCAL",
        "LOCAL_FIXTURE",
        "PUBLIC_RESEARCH_READONLY",
        "AUTHORIZED_TARGET_READONLY",
        "AUTHORIZED_TARGET_STATE_CHANGE",
    ]
    try:
        max_idx = profile_order.index(profile_value)
    except ValueError:
        return []
    allowed = set(profile_order[:max_idx + 1])
    return [b for b in LIBRARY_BLOCKS if b.profile_requirement in allowed]
