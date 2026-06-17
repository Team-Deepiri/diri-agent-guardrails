"""
Classic safety guardrails: prompt injection, blocked content, PII, output checks.

Delegates to the ``checkers`` module for all detection logic.
This module exists for backward compatibility; new code should use
``checkers`` directly.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Type

from diri_agent_guardrails.checkers.content import ContentSafetyChecker
from diri_agent_guardrails.checkers.format import FormatChecker
from diri_agent_guardrails.checkers.injection import InjectionChecker
from diri_agent_guardrails.checkers.pii import PIIChecker

logger = logging.getLogger(__name__)


class SafetyLevel(str, Enum):
    SAFE = "safe"
    WARNING = "warning"
    BLOCKED = "blocked"
    CRITICAL = "critical"


@dataclass
class SafetyCheckResult:
    level: SafetyLevel
    message: str
    score: float
    details: Dict[str, Any] = field(default_factory=dict)


class SafetyGuardrails:
    """
    Content filtering, prompt injection detection, and output validation for AI interactions.

    Backward-compatible wrapper around the ``checkers.*`` consolidated validators.
    """

    def __init__(self) -> None:
        self.logger = logger
        self._injection = InjectionChecker()
        self._content = ContentSafetyChecker()
        self._pii = PIIChecker()
        self._format = FormatChecker()

    def check_prompt(self, prompt: str, user_id: Optional[str] = None) -> SafetyCheckResult:
        checks: List[SafetyCheckResult] = []
        max_score = 0.0

        injection_result = self._check_prompt_injection(prompt)
        checks.append(injection_result)
        max_score = max(max_score, injection_result.score)

        content_result = self._check_blocked_content(prompt)
        checks.append(content_result)
        max_score = max(max_score, content_result.score)

        pii_result = self._check_pii(prompt)
        checks.append(pii_result)
        max_score = max(max_score, pii_result.score)

        if max_score >= 0.8:
            level = SafetyLevel.CRITICAL
        elif max_score >= 0.6:
            level = SafetyLevel.BLOCKED
        elif max_score >= 0.3:
            level = SafetyLevel.WARNING
        else:
            level = SafetyLevel.SAFE

        message = f"Prompt safety check: {level.value} (score: {max_score:.2f})"

        return SafetyCheckResult(
            level=level,
            message=message,
            score=max_score,
            details={
                "checks": [c.__dict__ for c in checks],
                "user_id": user_id,
                "timestamp": datetime.now().isoformat(),
            },
        )

    def _check_prompt_injection(self, prompt: str) -> SafetyCheckResult:
        result = self._injection.check(prompt)
        if not result.passed:
            return SafetyCheckResult(
                level=SafetyLevel.BLOCKED,
                message=result.message,
                score=result.score,
                details=result.details,
            )
        return SafetyCheckResult(
            level=SafetyLevel.SAFE,
            message="No prompt injection detected",
            score=0.0,
        )

    def _check_blocked_content(self, text: str) -> SafetyCheckResult:
        result = self._content.check(text)
        if not result.passed:
            is_block = result.verdict.value == "block"
            return SafetyCheckResult(
                level=SafetyLevel.BLOCKED if is_block else SafetyLevel.WARNING,
                message=result.message,
                score=result.score,
                details=result.details,
            )
        return SafetyCheckResult(
            level=SafetyLevel.SAFE,
            message="No blocked content detected",
            score=0.0,
        )

    def _check_pii(self, text: str) -> SafetyCheckResult:
        result = self._pii.check(text)
        if not result.passed:
            return SafetyCheckResult(
                level=SafetyLevel.WARNING,
                message=result.message,
                score=result.score,
                details=result.details,
            )
        return SafetyCheckResult(
            level=SafetyLevel.SAFE,
            message="No PII detected",
            score=0.0,
        )

    def check_output(
        self,
        output: str,
        expected_format: Optional[str] = None,
        max_length: Optional[int] = None,
    ) -> SafetyCheckResult:
        checks: List[SafetyCheckResult] = []
        max_score = 0.0

        if max_length and len(output) > max_length:
            checks.append(
                SafetyCheckResult(
                    level=SafetyLevel.WARNING,
                    message=f"Output exceeds max length: {len(output)} > {max_length}",
                    score=0.5,
                )
            )
            max_score = 0.5

        fmt_result = self._format.check(output, expected_format=expected_format)
        if not fmt_result.passed:
            checks.append(
                SafetyCheckResult(
                    level=SafetyLevel.WARNING,
                    message=fmt_result.message,
                    score=fmt_result.score,
                    details=fmt_result.details,
                )
            )
            max_score = max(max_score, fmt_result.score)

        content_result = self._check_blocked_content(output)
        checks.append(content_result)
        max_score = max(max_score, content_result.score)

        if max_score >= 0.6:
            level = SafetyLevel.BLOCKED
        elif max_score >= 0.3:
            level = SafetyLevel.WARNING
        else:
            level = SafetyLevel.SAFE

        return SafetyCheckResult(
            level=level,
            message=f"Output safety check: {level.value}",
            score=max_score,
            details={"checks": [c.__dict__ for c in checks]},
        )

    def validate_tool_output(
        self,
        tool_name: str,
        output: Any,
        expected_type: Optional[Type[Any]] = None,
    ) -> SafetyCheckResult:
        try:
            if expected_type and not isinstance(output, expected_type):
                return SafetyCheckResult(
                    level=SafetyLevel.WARNING,
                    message=(
                        f"Tool output type mismatch: expected {expected_type}, "
                        f"got {type(output)}"
                    ),
                    score=0.4,
                )

            if isinstance(output, str):
                return self.check_output(output)

            return SafetyCheckResult(
                level=SafetyLevel.SAFE,
                message="Tool output validated",
                score=0.0,
            )

        except Exception as e:
            return SafetyCheckResult(
                level=SafetyLevel.WARNING,
                message=f"Tool output validation error: {str(e)}",
                score=0.5,
            )

    def should_block(self, result: SafetyCheckResult) -> bool:
        return result.level in (SafetyLevel.BLOCKED, SafetyLevel.CRITICAL)


def get_guardrails() -> SafetyGuardrails:
    return SafetyGuardrails()
