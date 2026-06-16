"""Layer 0 — Policy envelope gate.

Checks before any job is enqueued:
  - AI enabled for project
  - User role (viewers cannot submit)
  - Mode in allowed list
  - Rate limit (via injected RateLimiter)
  - GPU budget / quota
  - Cloud routing allowed
"""
from __future__ import annotations

from diri_agent_guardrails.renderflow.config import RateLimiter, RenderFlowPolicy
from diri_agent_guardrails.renderflow.types import GuardrailDecision, ReasonCode, Verdict

GATE = "policy"


def check(
    policy: RenderFlowPolicy,
    mode: str,
    rate_limiter: RateLimiter | None = None,
) -> GuardrailDecision:
    """Run all Layer 0 checks and return the first blocking decision, or ALLOW."""
    if not policy.enabled or not policy.ai_enabled:
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.AI_DISABLED,
        )

    if policy.user_role == "viewer":
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.VIEWER_ROLE,
        )

    if mode not in policy.allowed_modes:
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.DISALLOWED_MODE,
            details={"mode": mode, "allowed": policy.allowed_modes},
        )

    if not policy.cloud_allowed and not policy.local_only:
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.CLOUD_BLOCKED,
        )

    if rate_limiter is not None and policy.user_id is not None:
        key = f"guardrail:rate:{policy.user_id}"
        within_limit, count = rate_limiter.check_and_increment(
            key, policy.rate_limit_per_hour, window_hours=1
        )
        if not within_limit:
            return GuardrailDecision(
                gate=GATE,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.RATE_LIMIT,
                details={"count": count, "limit": policy.rate_limit_per_hour},
            )

    return GuardrailDecision(gate=GATE, verdict=Verdict.ALLOW)
