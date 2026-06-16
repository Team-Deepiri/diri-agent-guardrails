"""PII (personally identifiable information) detection checker.

Consolidates patterns previously duplicated across safety.py, advanced.py,
and renderflow/gates/prompt.py.
"""
from __future__ import annotations

import re
from typing import Any, Sequence

from diri_agent_guardrails.core.result import CheckResult
from diri_agent_guardrails.core.verdict import ReasonCode, Verdict

_DEFAULT_RULES: list[tuple[str, str]] = [
    (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "phone"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "credit_card"),
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "credit_card"),
    (r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+", "credential"),
    (r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*\S+", "credential"),
    (r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "email"),
]


class PIIChecker:
    """Detect PII in text.

    Parameters
    ----------
    rules
        Sequence of ``(regex_pattern, label)`` tuples. If None, uses a
        consolidated default set from safety.py, advanced.py, and the
        RenderFlow prompt gate.
    """

    def __init__(self, rules: Sequence[tuple[str, str]] | None = None) -> None:
        raw = list(rules) if rules is not None else _DEFAULT_RULES
        self._compiled: list[tuple[re.Pattern[str], str]] = [
            (re.compile(p, re.IGNORECASE), label) for p, label in raw
        ]

    def check(self, text: str, **context: Any) -> CheckResult:
        hits: list[dict[str, Any]] = []
        for pattern, label in self._compiled:
            matches = pattern.findall(text)
            if matches:
                hits.append({"type": label, "count": len(matches), "samples": matches[:3]})

        if hits:
            return CheckResult(
                passed=False,
                verdict=Verdict.REDACT,
                reason_code=ReasonCode.PII_DETECTED,
                score=min(0.7, 0.3 + len(hits) * 0.1),
                message=f"PII detected: {len(hits)} type(s)",
                details={"pii_types": hits},
            )

        return CheckResult(passed=True, message="No PII detected")
