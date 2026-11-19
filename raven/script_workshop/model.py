"""RAVEN Phase III — Script Workshop data models.

Defines ExecutionProfile, ScriptProject, and ScriptPlan — the core
data types for structured script lifecycle management.

CRITICAL:
  ExecutionProfile.AUTHORIZED_TARGET_STATE_CHANGE requires human approval.
  Scripts may NOT be executed outside their declared profile.
  Security authority: NONE.
  Scripts containing shell injection patterns are rejected at planning time.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Execution profile ─────────────────────────────────────────────────────────

class ExecutionProfile(str, Enum):
    """Declares the execution scope and network access level of a script.

    Profiles are ordered by privilege level:
      PURE_LOCAL < LOCAL_FIXTURE < PUBLIC_RESEARCH_READONLY <
      AUTHORIZED_TARGET_READONLY < AUTHORIZED_TARGET_STATE_CHANGE

    CRITICAL: Profiles are enforced by the policy gate and process guard.
      AUTHORIZED_TARGET_STATE_CHANGE requires explicit human approval each run.
    """
    PURE_LOCAL                   = "PURE_LOCAL"
    LOCAL_FIXTURE                = "LOCAL_FIXTURE"
    PUBLIC_RESEARCH_READONLY     = "PUBLIC_RESEARCH_READONLY"
    AUTHORIZED_TARGET_READONLY   = "AUTHORIZED_TARGET_READONLY"
    AUTHORIZED_TARGET_STATE_CHANGE = "AUTHORIZED_TARGET_STATE_CHANGE"

    def requires_human_approval(self) -> bool:
        return self == ExecutionProfile.AUTHORIZED_TARGET_STATE_CHANGE

    def allows_network(self) -> bool:
        return self in (
            ExecutionProfile.PUBLIC_RESEARCH_READONLY,
            ExecutionProfile.AUTHORIZED_TARGET_READONLY,
            ExecutionProfile.AUTHORIZED_TARGET_STATE_CHANGE,
        )

    def allows_state_change(self) -> bool:
        return self == ExecutionProfile.AUTHORIZED_TARGET_STATE_CHANGE

    def allows_fixture_reads(self) -> bool:
        return self in (
            ExecutionProfile.LOCAL_FIXTURE,
            ExecutionProfile.PUBLIC_RESEARCH_READONLY,
            ExecutionProfile.AUTHORIZED_TARGET_READONLY,
            ExecutionProfile.AUTHORIZED_TARGET_STATE_CHANGE,
        )


# ── Script status ─────────────────────────────────────────────────────────────

class ScriptStatus(str, Enum):
    DRAFT        = "DRAFT"         # initial state
    REVIEWED     = "REVIEWED"      # passed automated safety review
    APPROVED     = "APPROVED"      # approved for execution (human, for sensitive profiles)
    EXECUTED     = "EXECUTED"      # execution completed
    FAILED       = "FAILED"        # execution failed
    REJECTED     = "REJECTED"      # safety review failed


# ── Safety review result ──────────────────────────────────────────────────────

@dataclass
class SafetyReviewResult:
    """Result of automated safety review for a script."""
    passed: bool
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: str = ""


# Patterns that are always rejected regardless of profile
_REJECTED_PATTERNS: list[tuple[str, str]] = [
    (r"\bos\.system\s*\(", "os.system() is not allowed — use subprocess with list args"),
    (r"\bsubprocess\.run\s*\([^)]*shell\s*=\s*True", "shell=True is not allowed in subprocess.run"),
    (r"\beval\s*\(", "eval() is not allowed"),
    (r"\bexec\s*\(", "exec() is not allowed"),
    (r"\b__import__\s*\(", "__import__() is not allowed"),
    (r"\bopen\s*\([^)]*['\"]w['\"]", "File write is not allowed in scripts"),
    (r"\bsocket\.socket\s*\(", "Raw sockets are not allowed"),
    (r"\bimport\s+socket\b", "socket import is not allowed"),
    (r"\bctypes\b",  "ctypes is not allowed"),
    (r"\bparamiko\b", "paramiko (SSH) is not allowed"),
    (r"\bscapy\b",   "scapy (raw packet) is not allowed"),
]

# Patterns that are warnings (profile-dependent)
_WARNING_PATTERNS: list[tuple[str, str]] = [
    (r"\brequests\.(?:post|put|delete|patch)\s*\(",
     "HTTP state-changing method requires AUTHORIZED_TARGET_STATE_CHANGE profile"),
    (r"\bhttpx\.(?:post|put|delete|patch)\s*\(",
     "HTTP state-changing method requires AUTHORIZED_TARGET_STATE_CHANGE profile"),
]


def review_script_safety(
    source_code: str,
    profile: ExecutionProfile,
) -> SafetyReviewResult:
    """Perform automated safety review on a script's source code.

    Checks for prohibited patterns regardless of profile, and
    profile-specific patterns that are warnings or rejections.

    CRITICAL: This review is a best-effort educational safeguard only.
      Human review is still required for AUTHORIZED_TARGET_STATE_CHANGE.
    """
    violations: list[str] = []
    warnings: list[str] = []

    for pattern, message in _REJECTED_PATTERNS:
        if re.search(pattern, source_code, re.MULTILINE | re.IGNORECASE):
            violations.append(message)

    for pattern, message in _WARNING_PATTERNS:
        if re.search(pattern, source_code, re.MULTILINE | re.IGNORECASE):
            if not profile.allows_state_change():
                violations.append(
                    f"Profile {profile.value} does not allow state-changing requests: {message}")
            else:
                warnings.append(message)

    # Network access check
    if (re.search(r'\b(?:requests|httpx|urllib|aiohttp)\b', source_code)
            and not profile.allows_network()):
        violations.append(
            f"Network access not allowed in profile {profile.value}")

    return SafetyReviewResult(
        passed=len(violations) == 0,
        violations=violations,
        warnings=warnings,
    )


# ── Script plan ───────────────────────────────────────────────────────────────

@dataclass
class ScriptStep:
    """One step in a script execution plan."""
    step_id: str
    description: str
    code_snippet: str = ""
    requires_network: bool = False
    requires_state_change: bool = False


@dataclass
class ScriptPlan:
    """A plan for a script's execution, derived before code is written.

    Plans are reviewed for safety before the script is written.
    Each step must be compatible with the declared ExecutionProfile.
    """
    plan_id: str
    objective: str
    profile: ExecutionProfile
    steps: list[ScriptStep] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)  # what data the script reads
    output_description: str = ""
    safety_notes: list[str] = field(default_factory=list)
    data_source: str = "EDUCATIONAL_SYNTHETIC"

    def is_compatible_with_profile(self) -> bool:
        """Check if all steps are within the declared profile's capabilities."""
        for step in self.steps:
            if step.requires_network and not self.profile.allows_network():
                return False
            if step.requires_state_change and not self.profile.allows_state_change():
                return False
        return True


# ── Script project ────────────────────────────────────────────────────────────

@dataclass
class ScriptProject:
    """A managed script project with lifecycle, safety review, and bounded execution.

    Lifecycle: DRAFT → REVIEWED → (APPROVED for sensitive) → EXECUTED | FAILED | REJECTED

    CRITICAL:
      - AUTHORIZED_TARGET_STATE_CHANGE requires explicit human approval
      - Safety review must pass before status can advance past DRAFT
      - Scripts may only perform operations within their declared profile
      - Security authority: NONE — scripts are not security tools
    """
    project_id: str
    name: str
    description: str
    profile: ExecutionProfile
    plan: ScriptPlan
    source_code: str = ""
    status: ScriptStatus = ScriptStatus.DRAFT
    safety_review: Optional[SafetyReviewResult] = None
    execution_log: list[str] = field(default_factory=list)
    created_at_ms: int = 0
    workspace_id: str = ""
    data_source: str = "EDUCATIONAL_SYNTHETIC"

    def __post_init__(self) -> None:
        if not self.project_id:
            raise ValueError("project_id must not be empty")
        if not self.name:
            raise ValueError("name must not be empty")
        if self.plan.profile != self.profile:
            raise ValueError(
                f"plan profile {self.plan.profile!r} must match project profile {self.profile!r}")

    def submit_for_review(self) -> SafetyReviewResult:
        """Run automated safety review on the current source_code."""
        if self.status != ScriptStatus.DRAFT:
            raise ValueError(f"Cannot review from status {self.status!r}")
        result = review_script_safety(self.source_code, self.profile)
        self.safety_review = result
        if result.passed:
            self.status = ScriptStatus.REVIEWED
        else:
            self.status = ScriptStatus.REJECTED
        return result

    def approve(self) -> None:
        """Mark as approved for execution (required for AUTHORIZED_TARGET_STATE_CHANGE)."""
        if self.status != ScriptStatus.REVIEWED:
            raise ValueError(f"Cannot approve from status {self.status!r}")
        self.status = ScriptStatus.APPROVED

    def is_executable(self) -> bool:
        """True if the project is in a runnable state."""
        if self.profile.requires_human_approval():
            return self.status == ScriptStatus.APPROVED
        return self.status in (ScriptStatus.REVIEWED, ScriptStatus.APPROVED)

    def to_summary_dict(self) -> dict:
        return {
            "project_id": self.project_id,
            "name": self.name,
            "profile": self.profile.value,
            "status": self.status.value,
            "safety_review_passed": self.safety_review.passed if self.safety_review else None,
            "violations": self.safety_review.violations if self.safety_review else [],
            "data_source": self.data_source,
        }
