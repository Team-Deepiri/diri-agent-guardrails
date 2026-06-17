"""Output format validation checker.

Consolidates format checks previously embedded in safety.py (JSON,
length, expected type).
"""
from __future__ import annotations

import json
from typing import Any

from diri_agent_guardrails.core.result import CheckResult
from diri_agent_guardrails.core.verdict import ReasonCode, Verdict


class FormatChecker:
    """Validate output format (JSON, length, type).

    Parameters
    ----------
    max_length
        Maximum allowed output length. ``None`` disables length checks.
    """

    def __init__(self, max_length: int | None = None) -> None:
        self._max_length = max_length

    def check(self, text: str, **context: Any) -> CheckResult:
        checks: list[CheckResult] = []

        if self._max_length is not None and len(text) > self._max_length:
            checks.append(CheckResult(
                passed=False,
                verdict=Verdict.WARN,
                reason_code=ReasonCode.INPUT_TOO_LONG,
                score=0.5,
                message=f"Output exceeds max length: {len(text)} > {self._max_length}",
                details={"length": len(text), "limit": self._max_length},
            ))

        expected_format = context.get("expected_format")
        if expected_format == "json":
            try:
                json.loads(text)
            except json.JSONDecodeError as e:
                checks.append(CheckResult(
                    passed=False,
                    verdict=Verdict.WARN,
                    reason_code=ReasonCode.OUTPUT_INVALID,
                    score=0.3,
                    message=f"Output is not valid JSON: {e}",
                ))

        expected_type = context.get("expected_type")
        if expected_type is not None and not isinstance(text, expected_type):
            checks.append(CheckResult(
                passed=False,
                verdict=Verdict.WARN,
                reason_code=ReasonCode.OUTPUT_INVALID,
                score=0.4,
                message=f"Output type mismatch: expected {expected_type}, got {type(text)}",
            ))

        if checks:
            worst = max(checks, key=lambda c: c.score)
            return CheckResult(
                passed=False,
                verdict=worst.verdict,
                reason_code=worst.reason_code,
                score=worst.score,
                message=worst.message,
                details={"checks": [c.to_dict() for c in checks]},
            )

        return CheckResult(passed=True, message="Format check passed")
