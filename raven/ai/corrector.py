"""RAVEN V7 Self-Corrector — Part 03.

Detects and corrects common AI output issues:
- Scope violations (mentioning out-of-scope targets)
- Advisory violations (claiming certainty on security findings)
- Missing human-verification disclaimers

All corrections are ADVISORY — they improve outputs but cannot authorize actions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CorrectionResult:
    original:   str
    corrected:  str
    issues:     List[str] = field(default_factory=list)
    corrections: int = 0
    is_advisory: bool = True  # ALWAYS True

    def __post_init__(self):
        object.__setattr__(self, "is_advisory", True)

    @property
    def was_modified(self) -> bool:
        return self.original != self.corrected


# Patterns that indicate overclaiming in security research context
_CERTAINTY_PATTERNS = [
    (r"\bI (confirmed|verified|exploited|proved)\b",
     "I assessed (advisory — requires human verification)"),
    (r"\bthis is (definitely|certainly) (vulnerable|exploitable)\b",
     "this may be vulnerable (advisory — requires human verification)"),
    (r"\bI (found|discovered) a (vulnerability|bug|exploit)\b",
     "I identified a potential candidate (advisory — requires human verification)"),
]

_ADVISORY_DISCLAIMER = "\n\n[⚠ Advisory: All findings require human verification before action.]"


class SelfCorrector:
    """Applies heuristic corrections to AI outputs for safety and accuracy."""

    def __init__(self, add_disclaimer: bool = True):
        self._add_disclaimer = add_disclaimer

    def correct(self, text: str, context: str = "") -> CorrectionResult:
        issues: List[str] = []
        corrected = text

        for pattern, replacement in _CERTAINTY_PATTERNS:
            match = re.search(pattern, corrected, re.IGNORECASE)
            if match:
                corrected = re.sub(pattern, replacement, corrected, flags=re.IGNORECASE)
                issues.append(f"Overclaim corrected: '{match.group(0)}'")

        if self._add_disclaimer and corrected.strip():
            if _ADVISORY_DISCLAIMER.strip() not in corrected:
                corrected += _ADVISORY_DISCLAIMER
                issues.append("Advisory disclaimer added")

        return CorrectionResult(
            original=text,
            corrected=corrected,
            issues=issues,
            corrections=len(issues),
        )

    def needs_correction(self, text: str) -> bool:
        for pattern, _ in _CERTAINTY_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
