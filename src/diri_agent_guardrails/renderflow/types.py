"""Core types for the RenderFlow 6-layer guardrail system."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"
    REDACT = "redact"


class ReasonCode(str, Enum):
    AI_DISABLED = "AI_DISABLED"
    RATE_LIMIT = "RATE_LIMIT"
    POLICY_BLOCK = "POLICY_BLOCK"
    SAFETY_BLOCK = "SAFETY_BLOCK"
    COPYRIGHT_WARN = "COPYRIGHT_WARN"
    LIKENESS_BLOCK = "LIKENESS_BLOCK"
    CONSENT_REQUIRED = "CONSENT_REQUIRED"
    OUTPUT_BLOCK = "OUTPUT_BLOCK"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    PII_REDACTED = "PII_REDACTED"
    INJECTION_DETECTED = "INJECTION_DETECTED"
    PROMPT_TOO_LONG = "PROMPT_TOO_LONG"
    PLAN_UNSAFE = "PLAN_UNSAFE"
    TIER_CAP = "TIER_CAP"
    DURATION_CAP = "DURATION_CAP"
    CLOUD_BLOCKED = "CLOUD_BLOCKED"
    VIEWER_ROLE = "VIEWER_ROLE"
    DISALLOWED_MODE = "DISALLOWED_MODE"


@dataclass
class GuardrailDecision:
    gate: str
    verdict: Verdict
    reason_code: ReasonCode | None = None
    score: float | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "verdict": self.verdict.value,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "score": self.score,
            "details": self.details,
        }
