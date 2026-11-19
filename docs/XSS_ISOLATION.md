# XSS execution isolation — disabled after defensive review

## Current behavior

**Browser execution confirmation is disabled.** RAVEN retains reflection/context
analysis. Its results describe reflection evidence; they do not prove that script
executed and do not automatically confirm a vulnerability.

The former executor's browser-launch and confirmation-payload construction code
has been removed. The compatibility entry points fail closed:

- `isolation_status()` and `self_test_with_local_fixtures()` always return
  `ok: false`, `disabled: true`, an empty case list, and a reason.
- `verify_confirmation()` always returns `attempted: false`, `executed: false`,
  `disabled: true`, and a reason. It does not process a target or start a browser.
- A supplied fixture factory or logger is not invoked. A returned status is a new
  object, so modifying a previous result cannot enable execution.
- No cached success, direct module call, or previous browser installation enables
  this feature. There is no verification button or API action that can unlock it.

The API refuses execution-confirmation requests before sending an analysis probe.
Ordinary analysis remains available through its existing controlled HTTP path.
These statements describe the updated source; an older executable must be rebuilt
and separately verified before it reflects these changes.

## Why the previous isolation claim was withdrawn

The previous implementation used a separate browser process and temporary profile.
Those measures separated browser state from RAVEN's window, but did not establish
the stronger safety properties claimed in the earlier documentation:

1. Hostname resolver rules were treated as a network isolation boundary without
   independently enforcing destination addresses, ports, redirects, and every
   browser-initiated request. Browser traffic also bypassed RAVEN's shared sender.
2. The network self-test targeted a port after closing its listening socket. A
   rejected fetch could therefore mean there was no service to receive it, rather
   than prove that traffic was blocked. It did not observe a receiving server.
3. `capture_output` collected output before the size check. Truncating the returned
   text did not bound memory used while collecting stdout and stderr.
4. Killing the direct subprocess did not establish termination of its descendants.
   Cleanup ignored profile-deletion errors; the tests did not verify that every
   browser process had exited.
5. Self-tests shared mutable fixture state, and an exception during a repeat test
   could leave a previous successful status in place.

Passing the old four-case self-test did not resolve these issues. Prior “verified
isolation” results should not be used as assurance of network containment or
complete cleanup.

## Requirements before reconsidering browser execution

A future design would need independent review of network containment, integration
with scope and request controls, process-tree lifetime and concurrency limits,
bounded output capture, deterministic cleanup, and fail-closed state transitions.
Verification would need controlled local observers and reachability controls that
distinguish an actual blocked request from an absent service or inaccessible
response. A successful run on one workstation would still not establish release
readiness across supported Windows environments.

This repair does not implement such an engine. It removes the unsafe execution
path while retaining analysis.

## Regression coverage

`tests/test_xss_executor.py` checks that direct calls and repeated verification
attempts remain disabled, that callers cannot enable execution by modifying a
returned status, and that supplied fixtures/callbacks are not invoked. Process,
network, and temporary-profile creation entry points are mocked to fail if called.
These tests do not start a browser, execute a payload, or contact a target.

`tests/test_xss_lab.py` covers the API refusal and the existing local analysis
behavior. A security property failing its tests must be reported as a failure,
not converted into a successful isolation claim.