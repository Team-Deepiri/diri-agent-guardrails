"""Prompt injection detection checker.

Consolidates patterns previously duplicated across safety.py, advanced.py,
and renderflow/gates/prompt.py.
"""
from __future__ import annotations

import re
from typing import Any, Sequence

from diri_agent_guardrails.core.result import CheckResult
from diri_agent_guardrails.core.verdict import ReasonCode, Verdict

_DEFAULT_PATTERNS: list[str] = [
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
    r"system\s*:\s*",
    r"new\s+instructions?",
    r"jailbreak|bypass|override",
    r"disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|guidelines?|rules?|prompts?)",
    r"forget\s+(?:everything|all)\s+(?:above|before|prior)",
    r"<\|?(?:system|assistant|user)\|?>",
    r"pretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:evil|unrestricted|jailbroken)",
    r"DAN\s+mode|developer\s+mode\s+enabled",
    r"new\s+(?:system\s+)?instructions?\s*:",
    r"bypass\s+(?:safety|restrictions?|filters?)",
]


class InjectionChecker:
    """Check text for prompt injection attempts.

    Parameters
    ----------
    patterns
        Regex patterns to match. If None, uses a consolidated default set
        drawn from safety.py, advanced.py, and the RenderFlow prompt gate.
    """

    def __init__(self, patterns: Sequence[str] | None = None) -> None:
        raw = list(patterns) if patterns is not None else _DEFAULT_PATTERNS
        self._compiled = [re.compile(p, re.IGNORECASE) for p in raw]

    def check(self, text: str, **context: Any) -> CheckResult:
        for pattern in self._compiled:
            match = pattern.search(text)
            if match:
                return CheckResult(
                    passed=False,
                    verdict=Verdict.BLOCK,
                    reason_code=ReasonCode.INJECTION_DETECTED,
                    score=0.95,
                    message=f"Injection pattern matched: {match.group()[:80]}",
                    details={"matched_pattern": pattern.pattern, "match": match.group()},
                )
        return CheckResult(passed=True, verdict=Verdict.ALLOW, message="No injection detected")
