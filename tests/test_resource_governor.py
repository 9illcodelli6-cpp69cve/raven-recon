"""Behavioral tests for the ResourceGovernor (A2-PROC, Wave 2).

Assert that: concurrency ceilings are actually enforced, admit() releases on
exception (no counter leak), training is disabled by default, network rate is
delegated to the scheduler (never metered here), and admission is refused under
emergency stop. Written to fail against a broken implementation.
"""
import threading
import time

import pytest

from raven.runtime.resource_governor import (
    ResourceAdmissionTimeout,
    ResourceDenied,
    ResourceGovernor,
    ResourceProfile,
    SAFE_DESKTOP,
)


def test_default_profile_is_safe_desktop():
    g = ResourceGovernor()
    assert g.profile is SAFE_DESKTOP
    assert g.profile.name == "SAFE_DESKTOP"
    assert g.limit("process") == 4
    assert g.limit("inference") == 1
    assert g.limit("training") == 0


def test_process_concurrency_capped_and_released():
    g = ResourceGovernor(ResourceProfile(name="t", max_processes=2))
    l1 = g.acquire("process")
    l2 = g.acquire("process")
    assert g.in_use("process") == 2
    with pytest.raises(ResourceAdmissionTimeout):
        g.acquire("process", timeout=0.2)
    g.release(l1)
    l3 = g.acquire("process", timeout=1.0)
    assert l3 is not None
    assert g.in_use("process") == 2
    g.release(l2)
    g.release(l3)
    assert g.in_use("process") == 0


def test_admit_context_manager_releases_on_exception():
    g = ResourceGovernor(ResourceProfile(name="t", max_processes=1))
    with pytest.raises(RuntimeError):
        with g.admit("process"):
            assert g.in_use("process") == 1
            raise RuntimeError("boom")
    assert g.in_use("process") == 0
    # capacity fully restored
    l = g.acquire("process", timeout=0.5)
    assert l is not None
    g.release(l)


def test_double_release_does_not_inflate_capacity():
    g = ResourceGovernor(ResourceProfile(name="t", max_processes=1))
    l = g.acquire("process")
    g.release(l)
    g.release(l)  # no-op; must not add a phantom slot
    l2 = g.acquire("process")
    with pytest.raises(ResourceAdmissionTimeout):
        g.acquire("process", timeout=0.2)
    g.release(l2)


def test_inference_serialized():
    g = ResourceGovernor()  # max_inference=1
    l = g.acquire("inference")
    with pytest.raises(ResourceAdmissionTimeout):
        g.acquire("inference", timeout=0.2)
    g.release(l)
    l2 = g.acquire("inference", timeout=0.5)
    assert l2 is not None
    g.release(l2)


def test_training_disabled_by_default():
    g = ResourceGovernor()
    with pytest.raises(ResourceDenied):
        g.acquire("training")
    with pytest.raises(ResourceDenied):
        with g.admit("training"):
            pass


def test_network_delegated_to_scheduler():
    g = ResourceGovernor()
    with pytest.raises(ResourceDenied) as ei:
        g.acquire("network")
    assert "scheduler" in str(ei.value).lower()
    # The governor keeps NO network meter.
    assert "network" not in g.snapshot()["limits"]
    assert g.snapshot()["network_rate"] == "delegated_to_scheduler"


def test_emergency_stop_refuses_admission():
    g = ResourceGovernor(emergency_stop=lambda: True)
    with pytest.raises(ResourceDenied):
        g.acquire("process")
    with pytest.raises(ResourceDenied):
        with g.admit("process"):
            pass


def test_unknown_dimension_refused():
    g = ResourceGovernor()
    with pytest.raises(ResourceDenied):
        g.acquire("gpu")


def test_snapshot_shape():
    g = ResourceGovernor()
    s = g.snapshot()
    assert s["profile"] == "SAFE_DESKTOP"
    assert s["limits"]["process"] == 4
    assert s["limits"]["training"] == 0
    assert s["in_use"]["process"] == 0
    assert s["advisory"]["max_workers"] == 3
    assert s["advisory"]["max_http_handlers"] == 64


def test_concurrency_under_threads():
    """A real multi-thread check that the semaphore bounds concurrent holders."""
    g = ResourceGovernor(ResourceProfile(name="t", max_processes=3))
    peak = {"v": 0}
    cur = {"v": 0}
    lock = threading.Lock()
    start = threading.Event()

    def worker():
        start.wait()
        with g.admit("process", timeout=5.0):
            with lock:
                cur["v"] += 1
                peak["v"] = max(peak["v"], cur["v"])
            time.sleep(0.05)
            with lock:
                cur["v"] -= 1

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join(timeout=10)
    assert peak["v"] <= 3
    assert g.in_use("process") == 0
