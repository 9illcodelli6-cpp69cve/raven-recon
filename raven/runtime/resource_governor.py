"""RAVEN canonical resource governance (Wave 2 — A2-PROC).

`ResourceGovernor` is the single process-wide **admission gate** that bounds
concurrency for the dimensions the live scheduler does NOT cover: OS-process
concurrency, worker/handler ceilings (advisory), CPU/memory soft ceilings, and
training/inference concurrency.

It is NOT a limiter re-implementation and, crucially, it adds **no second network
limiter**: per-host network rate and the per-workspace request budget remain the
sole responsibility of ``raven.api.scheduler.Scheduler`` (its ``TokenBucket`` and
budget ledger). Asking the governor to admit a ``"network"`` lease is therefore a
programming error and is refused with a pointer to the scheduler.

Canonical home per CANONICAL_ARCHITECTURE §1 row 3 and PROCESS_ARCHITECTURE §3.3.
The only profile shipped in this wave is :data:`SAFE_DESKTOP`; ``SERVER``/``CI``
presets are intentionally left for a later wave.

Usage (the executor consults this before every spawn)::

    gov = ResourceGovernor()                       # SAFE_DESKTOP
    with gov.admit("process", profile=exec_profile):
        ...spawn the child...
    # slot is released on normal exit AND on exception (no counter leak)

A non-context ``acquire``/``release`` pair is also provided for callers that
cannot use a ``with`` block; ``admit`` is preferred because it guarantees release.
"""
from __future__ import annotations

import contextlib
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional


# ── Errors ──────────────────────────────────────────────────────────────────

class ResourceGovernorError(Exception):
    """Base class for governor admission failures."""


class ResourceDenied(ResourceGovernorError):
    """Admission refused outright (disabled dimension, emergency stop, or a
    dimension the governor delegates elsewhere such as network rate)."""


class ResourceAdmissionTimeout(ResourceGovernorError):
    """A bounded ``acquire`` could not obtain a slot before the timeout."""


# ── Profile ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ResourceProfile:
    """Concurrency ceilings for one operating posture.

    ``max_workers`` and ``max_http_handlers`` are *advisory* ceilings other
    subsystems READ (the scheduler pool size, the HTTP accept path); the governor
    does not itself own those pools, it only publishes the recommended cap.
    ``cpu_soft_ceiling`` / ``mem_soft_ceiling`` are percentages (0..100) used for
    best-effort backpressure when ``psutil`` is present; absent psutil they are
    inert (never a hard kill).
    """
    name:             str
    max_processes:    int   = 4
    max_workers:      int   = 3       # advisory: scheduler pool ceiling
    max_http_handlers: int  = 64      # advisory: ThreadingHTTPServer accept cap
    cpu_soft_ceiling: float = 85.0    # percent; psutil backpressure if available
    mem_soft_ceiling: float = 85.0    # percent
    max_training:     int   = 0       # disabled by default (CLI-only elsewhere)
    max_inference:    int   = 1       # serialized; third-party/off by default


SAFE_DESKTOP = ResourceProfile(
    name="SAFE_DESKTOP",
    max_processes=4,
    max_workers=3,
    max_http_handlers=64,
    cpu_soft_ceiling=85.0,
    mem_soft_ceiling=85.0,
    max_training=0,
    max_inference=1,
)

# Dimensions the governor actually meters with a semaphore.
_METERED = ("process", "inference", "training")
# Dimensions explicitly delegated to another authority.
_DELEGATED = {
    "network": "network rate/budget is governed by raven.api.scheduler.Scheduler "
               "(TokenBucket + per-workspace budget), never by the ResourceGovernor",
}


# ── Internals ─────────────────────────────────────────────────────────────────

class _Gate:
    """A counting gate with a fixed capacity and an in-use counter.

    Capacity 0 means the dimension is disabled: every acquire is refused.
    """

    def __init__(self, capacity: int):
        self.capacity = max(0, int(capacity))
        self._sem = threading.Semaphore(self.capacity) if self.capacity > 0 else None
        self._lock = threading.Lock()
        self._in_use = 0

    def acquire(self, timeout: Optional[float]) -> bool:
        if self.capacity <= 0 or self._sem is None:
            return False
        if timeout is None:
            ok = self._sem.acquire(blocking=True)
        else:
            ok = self._sem.acquire(blocking=True, timeout=timeout)
        if ok:
            with self._lock:
                self._in_use += 1
        return bool(ok)

    def release(self) -> None:
        if self.capacity <= 0 or self._sem is None:
            return
        with self._lock:
            if self._in_use <= 0:
                return  # guard against double-release inflating capacity
            self._in_use -= 1
        self._sem.release()

    @property
    def in_use(self) -> int:
        with self._lock:
            return self._in_use


@dataclass
class Lease:
    """A held admission slot. Returned by ``acquire``; consumed by ``release``."""
    kind:          str
    profile:       Optional[str] = None
    acquired_at:   float = field(default_factory=time.monotonic)
    released:      bool = False
    _gate:         Optional[_Gate] = None

    @property
    def held_ms(self) -> int:
        return int((time.monotonic() - self.acquired_at) * 1000)


# ── Governor ──────────────────────────────────────────────────────────────────

class ResourceGovernor:
    """Process-wide admission gate (default profile :data:`SAFE_DESKTOP`).

    Parameters
    ----------
    profile:
        The active :class:`ResourceProfile`. Defaults to ``SAFE_DESKTOP``.
    emergency_stop:
        Optional zero-arg predicate returning ``True`` when a global emergency
        stop is active. When it returns ``True`` every admission is refused. The
        default is a safe no-op (``lambda: False``) so a later wave can inject
        ``PolicyGate.is_emergency_stop_active`` without this module importing it.
    enable_pressure_check:
        When ``True`` *and* ``psutil`` is importable, ``admit("process")`` also
        applies a CPU/memory soft-ceiling backpressure. Default ``False`` so the
        governor has no third-party dependency and deterministic behavior.
    """

    def __init__(
        self,
        profile: ResourceProfile = SAFE_DESKTOP,
        *,
        emergency_stop: Optional[Callable[[], bool]] = None,
        enable_pressure_check: bool = False,
    ):
        self.profile = profile
        self._emergency_stop = emergency_stop or (lambda: False)
        self._enable_pressure = bool(enable_pressure_check)
        self._gates: Dict[str, _Gate] = {
            "process":   _Gate(profile.max_processes),
            "inference": _Gate(profile.max_inference),
            "training":  _Gate(profile.max_training),
        }
        self._psutil = None
        if self._enable_pressure:
            try:  # best-effort; never a hard dependency
                import psutil  # type: ignore
                self._psutil = psutil
            except Exception:
                self._psutil = None

    # -- core acquire/release --------------------------------------------------

    def acquire(self, kind: str = "process", *, timeout: Optional[float] = None,
                profile: Optional[str] = None) -> Lease:
        """Acquire one slot for ``kind``; returns a :class:`Lease`.

        Raises :class:`ResourceDenied` when the dimension is disabled, delegated,
        or an emergency stop is active; :class:`ResourceAdmissionTimeout` when a
        bounded wait expires.
        """
        if kind in _DELEGATED:
            raise ResourceDenied(_DELEGATED[kind])
        if kind not in self._gates:
            raise ResourceDenied(f"unknown resource dimension: {kind!r}")
        if self._emergency_stop():
            raise ResourceDenied("emergency_stop_active")

        gate = self._gates[kind]
        if gate.capacity <= 0:
            raise ResourceDenied(f"{kind} concurrency is disabled by profile "
                                 f"{self.profile.name!r}")

        if kind == "process" and not self._pressure_ok():
            raise ResourceDenied("system under CPU/memory pressure")

        if not gate.acquire(timeout):
            raise ResourceAdmissionTimeout(
                f"could not admit {kind!r} within {timeout}s "
                f"(limit={gate.capacity}, in_use={gate.in_use})")
        return Lease(kind=kind, profile=profile, _gate=gate)

    def release(self, lease: Lease) -> None:
        if lease is None or lease.released:
            return
        lease.released = True
        if lease._gate is not None:
            lease._gate.release()

    @contextlib.contextmanager
    def admit(self, kind: str = "process", *, timeout: Optional[float] = None,
              profile: Optional[str] = None):
        """Context manager that acquires on enter and ALWAYS releases on exit.

        This is the preferred API: release happens in ``finally`` so an exception
        in the governed body can never leak a slot (the counter-leak hazard called
        out in RAVEN_CONCURRENCY_MAP §84).
        """
        lease = self.acquire(kind, timeout=timeout, profile=profile)
        try:
            yield lease
        finally:
            self.release(lease)

    # -- introspection ---------------------------------------------------------

    def in_use(self, kind: str = "process") -> int:
        gate = self._gates.get(kind)
        return gate.in_use if gate else 0

    def limit(self, kind: str = "process") -> int:
        gate = self._gates.get(kind)
        return gate.capacity if gate else 0

    def snapshot(self) -> dict:
        """A JSON-safe view of ceilings, in-use counts, and advisory values."""
        return {
            "profile": self.profile.name,
            "limits": {k: g.capacity for k, g in self._gates.items()},
            "in_use": {k: g.in_use for k, g in self._gates.items()},
            "advisory": {
                "max_workers": self.profile.max_workers,
                "max_http_handlers": self.profile.max_http_handlers,
                "cpu_soft_ceiling": self.profile.cpu_soft_ceiling,
                "mem_soft_ceiling": self.profile.mem_soft_ceiling,
            },
            "network_rate": "delegated_to_scheduler",
            "emergency_stop": bool(self._emergency_stop()),
        }

    # -- pressure (best-effort, psutil-optional) -------------------------------

    def _pressure_ok(self) -> bool:
        if not self._enable_pressure or self._psutil is None:
            return True
        try:
            cpu = self._psutil.cpu_percent(interval=None)
            mem = self._psutil.virtual_memory().percent
        except Exception:
            return True
        return cpu <= self.profile.cpu_soft_ceiling and mem <= self.profile.mem_soft_ceiling
