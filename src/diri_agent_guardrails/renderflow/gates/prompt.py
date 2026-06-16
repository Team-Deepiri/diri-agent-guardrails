"""Layer 1 — Input / prompt guard.

Checks (in order):
  1. Zero-tolerance patterns (S4 CSAM, S9 weapons) — no admin override
  2. Prompt length
  3. Org keyword blocklist
  4. Prompt injection + harmful content (via SafetyGuardrails)
  5. PII detection → REDACT verdict (caller strips PII from stored audit copy)
"""
from __future__ import annotations

import re
from typing import Sequence

from diri_agent_guardrails.renderflow.config import RenderFlowPolicy
from diri_agent_guardrails.renderflow.types import GuardrailDecision, ReasonCode, Verdict
from diri_agent_guardrails.safety import SafetyGuardrails

GATE = "prompt"

# Patterns that are always blocked regardless of org policy (S4 + S9 zero-tolerance)
_ZERO_TOLERANCE = re.compile(
    r"child\s*porn|csam|\bloli(?!pop)\b|\bshota\b|ncii"
    r"|synthesize\s+(?:sarin|vx gas|novichok|mustard\s+gas|nerve\s+agent)"
    r"|(?:how\s+to\s+)?(?:make|build|create)\s+(?:a\s+)?(?:dirty\s+bomb|bioweapon|biological\s+weapon)",
    re.IGNORECASE,
)

# Additional injection patterns not covered by SafetyGuardrails baseline
_INJECTION_EXTRA = re.compile(
    r"disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|guidelines?|rules?|prompts?)"
    r"|forget\s+(?:everything|all)\s+(?:above|before|prior)"
    r"|<\|?(?:system|assistant|user)\|?>"
    r"|pretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:evil|unrestricted|jailbroken)"
    r"|DAN\s+mode|developer\s+mode\s+enabled",
    re.IGNORECASE,
)

_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "ssn"),
    (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "credit_card"),
    (re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"), "phone"),
    (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "email"),
]

_safety = SafetyGuardrails()


def check(
    prompt: str,
    policy: RenderFlowPolicy,
    extra_blocklist: Sequence[str] | None = None,
) -> GuardrailDecision:
    """Run all Layer 1 input checks. Returns first non-ALLOW decision encountered."""

    # 1. Zero-tolerance — always block, no admin override (S4 / S9)
    if _ZERO_TOLERANCE.search(prompt):
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.SAFETY_BLOCK,
            score=1.0,
            details={"zero_tolerance": True},
        )

    # 2. Length
    if len(prompt) > policy.max_prompt_length:
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.PROMPT_TOO_LONG,
            details={"length": len(prompt), "limit": policy.max_prompt_length},
        )

    # 3. Org keyword / phrase blocklist
    if extra_blocklist:
        lower = prompt.lower()
        for term in extra_blocklist:
            if term.lower() in lower:
                return GuardrailDecision(
                    gate=GATE,
                    verdict=Verdict.BLOCK,
                    reason_code=ReasonCode.POLICY_BLOCK,
                    details={"blocklist_match": term},
                )

    # 4a. Supplemental injection patterns (broader than SafetyGuardrails baseline)
    if _INJECTION_EXTRA.search(prompt):
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.INJECTION_DETECTED,
            score=0.95,
            details={"injection_pattern": "extended"},
        )

    # 4b. Injection + harmful content (uses existing SafetyGuardrails)
    safety_result = _safety.check_prompt(prompt)
    if _safety.should_block(safety_result):
        is_injection = "injection" in safety_result.message.lower()
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.INJECTION_DETECTED if is_injection else ReasonCode.SAFETY_BLOCK,
            score=safety_result.score,
            details=safety_result.details,
        )

    # 5. PII — REDACT (not block); caller should strip PII from stored audit copy
    pii_hits = _detect_pii(prompt)
    if pii_hits:
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.REDACT,
            reason_code=ReasonCode.PII_REDACTED,
            details={"pii_types": pii_hits},
        )

    return GuardrailDecision(gate=GATE, verdict=Verdict.ALLOW, score=safety_result.score)


def _detect_pii(text: str) -> list[str]:
    found: list[str] = []
    for pattern, pii_type in _PII_PATTERNS:
        if pattern.search(text):
            found.append(pii_type)
    return found
