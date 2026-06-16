"""Content safety checker — blocked / harmful content patterns.

Consolidates patterns previously duplicated across safety.py and advanced.py.
"""
from __future__ import annotations

import re
from typing import Any, Sequence

from diri_agent_guardrails.core.result import CheckResult
from diri_agent_guardrails.core.verdict import ReasonCode, Verdict

_DEFAULT_PATTERNS: list[str] = [
    r"\b(?:explicit|nsfw|adult)\b",
    r"\b(?:violence|harm|kill|attack)\b",
    r"\b(?:hate|discriminate|slur)\b",
    r"\b(?:how\s+to\s+)?(?:make|create|build)\s+(?:a\s+)?(?:bomb|weapon|explosive)",
    r"\b(?:how\s+to\s+)?(?:harm|hurt|kill|attack)\s+(?:someone|people)",
    r"\b(?:synthesize|produce)\s+(?:drugs?|narcotics?|poison)",
]


class ContentSafetyChecker:
    """Check text against blocked / harmful content patterns.

    Parameters
    ----------
    patterns
        Regex patterns to match. If None, uses a consolidated default set
        drawn from safety.py and advanced.py.
    """

    def __init__(self, patterns: Sequence[str] | None = None) -> None:
        raw = list(patterns) if patterns is not None else _DEFAULT_PATTERNS
        self._compiled = [re.compile(p, re.IGNORECASE) for p in raw]

    def check(self, text: str, **context: Any) -> CheckResult:
        matches: list[str] = []
        for pattern in self._compiled:
            if pattern.search(text):
                matches.append(pattern.pattern)

        if matches:
            score = min(0.8, 0.4 + len(matches) * 0.2)
            return CheckResult(
                passed=False,
                verdict=Verdict.BLOCK if score >= 0.6 else Verdict.WARN,
                reason_code=ReasonCode.SAFETY_BLOCK if score >= 0.6 else ReasonCode.POLICY_VIOLATION,
                score=score,
                message=f"Blocked content patterns detected: {len(matches)} match(es)",
                details={"matched_patterns": matches},
            )

        return CheckResult(passed=True, message="No blocked content detected")
