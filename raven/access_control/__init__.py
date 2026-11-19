"""RAVEN Phase III — Access Control Academy.

Provides educational models for access control concepts:
  - Principal, Resource, Action, AccessTuple, AuthorizationMatrix
  - SEC-A: AuthorizationExperimentQuality classification rule
  - CandidateAuthorizationFinding (candidate only — never auto-verified)
  - Phase III fixture lab and graduation exam

INVARIANTS:
  - Security authority: NONE
  - human_verification_required is ALWAYS True on all findings
  - AuthorizationViolationType values are CONCEPTUAL LABELS, not confirmed findings
  - External targets contacted: 0
  - data_source: "EDUCATIONAL_SYNTHETIC" on all fixtures
  - Do NOT begin vulnerability-family training
"""
