# RAVEN V6 — PoC Architecture

## PoC Candidate Model (Gate 27)

`PoCCandidate` in `raven/poc/candidate.py` represents a candidate finding.
It is evidence-driven structured data, NOT executable exploit code.

### Scientific Reasoning Chain (Gate 28)

```
Hypothesis
  -> Preconditions
  -> Minimal Safe Experiment
  -> Control
  -> Observations
  -> Alternative Explanations
  -> Negative Controls
  -> Evidence References
  -> Candidate Conclusion
  -> HUMAN VERIFICATION (AUTHORITATIVE)
```

Human verification is non-negotiable. `can_be_promoted()` returns `False`
until `human_verified_by` is set and status is `HUMAN_VERIFIED`.

## Safe Action Primitives (Gate 29)

9 primitives defined in `raven/poc/primitives.py`:

| Primitive | Risk Class | Approval |
|---|---|---|
| establish_baseline | SafeReadOnly | automatic |
| repeat_request (N<=10) | SafeReadOnly | automatic |
| compare_response | SafeReadOnly | automatic |
| compare_identity | SafeReadOnly | automatic |
| replace_object_reference (GET) | SafeReadOnly | automatic |
| replace_object_reference (mutation) | LowRiskStateChange | researcher_approval |
| change_safe_parameter | LowRiskStateChange | automatic |
| observe_redirect | SafeReadOnly | automatic |
| record_evidence | SafeReadOnly | automatic |
| run_negative_control | SafeReadOnly | automatic |

**No `execute_arbitrary_command()`. No `open_arbitrary_socket()`. No `run_exploit()`.**

## Autonomy Levels (Gate 30)

Default: **LEVEL 1 — ASSIST**

| Level | Name | What RAVEN may do autonomously |
|---|---|---|
| 0 | MANUAL | Nothing — researcher executes everything |
| 1 | ASSIST (DEFAULT) | Analyze, rank, explain, propose, build PoC candidates |
| 2 | SUPERVISED | Also execute SafeReadOnly probes |
| 3 | BOUNDED_AUTO | Also execute LowRiskStateChange in pre-approved scope |

- Level 3 is NEVER globally enabled.
- Sensitive/Destructive/Exfiltrative always require human approval at ALL levels.
- ML/AI cannot set its own autonomy level.
