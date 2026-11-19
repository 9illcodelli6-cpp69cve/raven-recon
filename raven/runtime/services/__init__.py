"""Runtime-owned service layer (Wave 3 decomposition).

Thin services that `RavenRuntime` / the server composition root expose so route
bodies can delegate to `RUNTIME.<service>.<method>` instead of calling module
functions in `raven/api/server.py` directly. Each service is pure moved-out
server code; it never reconstructs a subsystem differently. See
reconstruction/RUNTIME_ARCHITECTURE.md §3.5 and CANONICAL_ARCHITECTURE §1.
"""
