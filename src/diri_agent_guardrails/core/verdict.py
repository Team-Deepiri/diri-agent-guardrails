"""Domain-agnostic guardrail verdicts and reason codes."""
from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    ESCALATE = "escalate"
    WARN = "warn"


class ReasonCode(str, Enum):
    POLICY_VIOLATION = "POLICY_VIOLATION"
    SAFETY_BLOCK = "SAFETY_BLOCK"
    INJECTION_DETECTED = "INJECTION_DETECTED"
    PII_DETECTED = "PII_DETECTED"
    RATE_LIMITED = "RATE_LIMITED"
    INPUT_TOO_LONG = "INPUT_TOO_LONG"
    OUTPUT_INVALID = "OUTPUT_INVALID"
    ESCALATED = "ESCALATED"
    CUSTOM = "CUSTOM"
