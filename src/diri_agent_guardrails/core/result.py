"""Generic guardrail check result."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from diri_agent_guardrails.core.verdict import ReasonCode, Verdict


@dataclass
class CheckResult:
    passed: bool = True
    verdict: Verdict = Verdict.ALLOW
    reason_code: ReasonCode | None = None
    score: float = 0.0
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    modified_content: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "verdict": self.verdict.value,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "score": self.score,
            "message": self.message,
            "details": self.details,
            "modified_content": self.modified_content,
            "timestamp": self.timestamp.isoformat(),
        }
