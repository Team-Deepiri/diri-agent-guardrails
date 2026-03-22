"""
Classic safety guardrails: prompt injection, blocked content, PII, output checks.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Type

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
    """

    def __init__(self) -> None:
        self.logger = logger
        self.blocked_patterns = self._load_blocked_patterns()
        self.pii_patterns = self._load_pii_patterns()
        self.injection_patterns = self._load_injection_patterns()

    def _load_blocked_patterns(self) -> List[re.Pattern[str]]:
        return [
            re.compile(r"\b(?:explicit|nsfw|adult)\b", re.IGNORECASE),
            re.compile(r"\b(?:violence|harm|kill|attack)\b", re.IGNORECASE),
            re.compile(r"\b(?:hate|discriminate|slur)\b", re.IGNORECASE),
        ]

    def _load_pii_patterns(self) -> List[Tuple[re.Pattern[str], str]]:
        return [
            (re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"), "phone"),
            (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "ssn"),
            (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "credit_card"),
        ]

    def _load_injection_patterns(self) -> List[re.Pattern[str]]:
        return [
            # "ignore previous …", "ignore all previous …", "ignore above …"
            re.compile(
                r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
                re.IGNORECASE,
            ),
            re.compile(r"system\s*:\s*", re.IGNORECASE),
            re.compile(r"new\s+instructions?", re.IGNORECASE),
            re.compile(r"jailbreak|bypass|override", re.IGNORECASE),
        ]

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
        matches: List[str] = []
        for pattern in self.injection_patterns:
            if pattern.search(prompt):
                matches.append(pattern.pattern)

        if matches:
            score = min(0.9, 0.5 + len(matches) * 0.1)
            return SafetyCheckResult(
                level=SafetyLevel.BLOCKED,
                message=f"Potential prompt injection detected: {len(matches)} patterns matched",
                score=score,
                details={"matched_patterns": matches},
            )

        return SafetyCheckResult(
            level=SafetyLevel.SAFE,
            message="No prompt injection detected",
            score=0.0,
        )

    def _check_blocked_content(self, text: str) -> SafetyCheckResult:
        matches: List[str] = []
        for pattern in self.blocked_patterns:
            if pattern.search(text):
                matches.append(pattern.pattern)

        if matches:
            score = min(0.8, 0.4 + len(matches) * 0.2)
            return SafetyCheckResult(
                level=SafetyLevel.WARNING if score < 0.6 else SafetyLevel.BLOCKED,
                message=f"Blocked content patterns detected: {len(matches)} matches",
                score=score,
                details={"matched_patterns": matches},
            )

        return SafetyCheckResult(
            level=SafetyLevel.SAFE,
            message="No blocked content detected",
            score=0.0,
        )

    def _check_pii(self, text: str) -> SafetyCheckResult:
        found_pii: List[Dict[str, Any]] = []
        for pattern, pii_type in self.pii_patterns:
            matches = pattern.findall(text)
            if matches:
                found_pii.append(
                    {
                        "type": pii_type,
                        "count": len(matches),
                        "samples": matches[:3],
                    }
                )

        if found_pii:
            score = min(0.7, 0.3 + len(found_pii) * 0.2)
            return SafetyCheckResult(
                level=SafetyLevel.WARNING,
                message=f"PII detected: {len(found_pii)} types",
                score=score,
                details={"pii_types": found_pii},
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

        content_result = self._check_blocked_content(output)
        checks.append(content_result)
        max_score = max(max_score, content_result.score)

        if expected_format == "json":
            try:
                json.loads(output)
            except json.JSONDecodeError:
                checks.append(
                    SafetyCheckResult(
                        level=SafetyLevel.WARNING,
                        message="Output is not valid JSON",
                        score=0.3,
                    )
                )
                max_score = max(max_score, 0.3)

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
