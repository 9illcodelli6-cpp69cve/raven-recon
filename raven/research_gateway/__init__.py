"""RAVEN Phase III — Research Gateway.

Provides PUBLIC_RESEARCH_READONLY access to public technical information
with source provenance tracking and prompt-injection resistance.

INVARIANTS:
  - All content from external sources is UNTRUSTED DATA, not instructions
  - Web pages CANNOT modify RAVEN policy, scope, capabilities, or system prompts
  - Source provenance is always recorded with retrieved content
  - Only public, non-interactive research URLs may be fetched
  - No credentials, session tokens, or API keys are sent with requests
  - No state-changing HTTP methods (POST/PUT/DELETE/PATCH) are issued
  - Security authority: NONE — research results ≠ confirmed findings
  - Retrieved content is quarantined from policy evaluation
"""
