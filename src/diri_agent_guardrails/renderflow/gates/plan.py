"""Layer 2 — Plan / storyboard guard.

Runs after RFIR plan_shots() generates a ShotList, before GPU compile.

Checks per shot:
  - Minor + explicit descriptor combo (zero-tolerance)
  - Safety classifier on shot description
  - Tier cap (downgrade if over policy.max_tier)

Aggregate checks:
  - Total duration cap
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from diri_agent_guardrails.renderflow.config import RenderFlowPolicy
from diri_agent_guardrails.renderflow.types import GuardrailDecision, ReasonCode, Verdict
from diri_agent_guardrails.safety import SafetyGuardrails

GATE = "plan"

_MINOR_PLUS_EXPLICIT = re.compile(
    r"(?:"
    r"\b(?:child|minor|kid|underage|preteen|teen(?:ager)?)\b"
    r".*"
    r"\b(?:nude|naked|intimate|sexual|explicit|erotic)\b"
    r"|"
    r"\b(?:nude|naked|intimate|sexual|explicit|erotic)\b"
    r".*"
    r"\b(?:child|minor|kid|underage|preteen|teen(?:ager)?)\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)

# Tier ordering: A (lowest compute) → D (highest)
_TIER_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3}

_safety = SafetyGuardrails()


@dataclass
class ShotEntry:
    description: str
    duration_sec: float = 5.0
    tier: str = "B"
    metadata: dict = field(default_factory=dict)


def check(
    shots: list[ShotEntry] | list[dict],
    policy: RenderFlowPolicy,
) -> GuardrailDecision:
    """Validate a plan (list of shots) against the active policy."""
    entries = [ShotEntry(**s) if isinstance(s, dict) else s for s in shots]

    # Aggregate duration check
    total_sec = sum(e.duration_sec for e in entries)
    if total_sec > policy.max_duration_sec:
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.DURATION_CAP,
            details={"total_sec": total_sec, "limit_sec": policy.max_duration_sec},
        )

    max_allowed_tier = _TIER_ORDER.get(policy.max_tier, 2)

    for i, shot in enumerate(entries):
        # Zero-tolerance: minor + explicit combo
        if _MINOR_PLUS_EXPLICIT.search(shot.description):
            return GuardrailDecision(
                gate=GATE,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.SAFETY_BLOCK,
                score=1.0,
                details={"shot_index": i, "reason": "minor+explicit descriptor"},
            )

        # Tier cap — downgrade silently rather than block
        shot_tier = _TIER_ORDER.get(shot.tier, 1)
        if shot_tier > max_allowed_tier:
            shot.tier = policy.max_tier
            shot.metadata["tier_capped"] = True

        # Per-shot content safety
        result = _safety.check_prompt(shot.description)
        if _safety.should_block(result):
            return GuardrailDecision(
                gate=GATE,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.PLAN_UNSAFE,
                score=result.score,
                details={"shot_index": i, "shot": shot.description[:120]},
            )

    return GuardrailDecision(gate=GATE, verdict=Verdict.ALLOW)
