"""RAVEN V7 Program Agent — Part 08.

Bug bounty program management:
- Program policy (scope, rules, exclusions)
- Target tracking within scope
- Submission management
- Rate limiting compliance

All operations are scope-validated.
external_targets = 0 is enforced by ProgramPolicy.
"""
from .policy import ProgramPolicy, ProgramScope, ScopeItem, ScopeType
from .program import BugBountyProgram, ProgramStore
from .submission import Submission, SubmissionStatus, SubmissionStore
from .registry import register_program_tools

__all__ = [
    "ProgramPolicy", "ProgramScope", "ScopeItem", "ScopeType",
    "BugBountyProgram", "ProgramStore",
    "Submission", "SubmissionStatus", "SubmissionStore",
    "register_program_tools",
]
