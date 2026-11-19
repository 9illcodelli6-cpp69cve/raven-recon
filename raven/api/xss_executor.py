"""Fail-closed compatibility interface for the retired XSS browser executor.

Reflection/context analysis remains available in ``server.do_xss_check``. This
module never creates a payload, starts a browser, or opens a network connection.
The former hostname-resolver rules and local self-test did not establish network
containment, so a cached success or a direct API call cannot enable execution.
"""

DISABLED_REASON = (
    "XSS execution confirmation is disabled: the former browser executor did not "
    "establish network containment, process-tree cleanup, or bounded output capture. "
    "Reflection/context analysis remains available without script execution."
)


class ExecutorUnavailable(RuntimeError):
    """Retained for callers that imported the former executor exception."""


def isolation_status():
    """Return a new, permanently disabled status; no cached success is trusted."""
    return {
        "ok": False,
        "disabled": True,
        "cases": [],
        "checked_at": None,
        "reason": DISABLED_REASON,
    }


def self_test_with_local_fixtures(fixture_server_factory=None, verbose_log=None):
    """Refuse verification without invoking fixtures, callbacks, or a browser.

    Arguments remain accepted for compatibility with older callers. There is no
    self-test that can enable the retired executor.
    """
    return isolation_status()


def verify_confirmation(url, token, timeout=None):
    """Refuse every direct confirmation request before processing its inputs."""
    return {
        "attempted": False,
        "executed": False,
        "disabled": True,
        "error": DISABLED_REASON,
        "reason": DISABLED_REASON,
    }