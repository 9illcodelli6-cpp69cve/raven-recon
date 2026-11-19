# Validation — RAVEN 0.1.0

Date: 2026-09-26

Environment: Linux container, Python 3.12.14, Textual 8.2.8, aiohttp 3.14.3.

## Verified

- 32 automated tests passed, including actual HTTP requests to local test servers.
- Domain/wildcard boundaries, exclusions, Unicode hostnames, credentials and custom ports.
- Redirects outside scope are not followed; in-scope relative redirects are processed.
- Non-public literal IPs and DNS answers are blocked by default.
- Request budgets, global pacing, bounded response bodies, request timeouts, cancellation and HTTP 429 handling.
- Saved imports, source attribution, deduplication, HTTP deltas and filtering after narrowing scope.
- Workspace write exclusion, preserving existing scope files and rejecting invalid configuration.
- Collector nonzero exits and stopping a running subprocess while preserving its partial output.
- TUI startup, filtering, row details, file import, report export and offline-demo collection guard.
- CLI init → import → JavaScript extraction → list → export workflow.
- Package wheel builds and includes Python modules and the TUI stylesheet.
- True-color TUI screenshot rendered from the working application and visually inspected.

## Limits of verification

- No access to the user's Kali machine was used; installation there is not yet verified.
- subfinder and gau executables were not installed in the build environment. Adapter execution was tested with controlled executable fixtures; live provider availability, API credentials and output completeness were not tested.
- No public target was probed during development or tests. TLS certificate errors remain enforced by aiohttp's default verification; there is no ignore-TLS option.
- This is an initial implementation, not a claim of exhaustive coverage, production hardening or automatic vulnerability confirmation.

Run the included tests with `python -m pytest -q` after installing `.[test]`.

