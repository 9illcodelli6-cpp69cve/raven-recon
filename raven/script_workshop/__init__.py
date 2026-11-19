"""RAVEN Phase III — Script Workshop.

Educational module for structured, policy-enforced script generation,
planning, and bounded execution.

INVARIANTS:
  - Scripts are generated and reviewed BEFORE execution
  - ExecutionProfile limits scope — never exceeded
  - AUTHORIZED_TARGET_STATE_CHANGE requires explicit human approval
  - No unrestricted shell agent; no scope bypass; no credential harvesting
  - Security authority: NONE
  - External target contacts: 0 unless explicitly authorized via policy_gate
"""
