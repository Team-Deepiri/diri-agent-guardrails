"""RenderFlow 6-layer guardrail system.

Extends the base diri-agent-guardrails package with RenderFlow-specific
policy configuration, presets, and per-layer gate implementations.

Quick start::

    from diri_agent_guardrails.renderflow.presets import build_policy
    from diri_agent_guardrails.renderflow.gates import policy, prompt, plan, output

    rf_policy = build_policy("us_default", user_id="u1", project_id="p1")

    decision = policy.check(rf_policy, mode="scene")
    if decision.blocked:
        raise HTTPException(403, decision.reason_code)

    decision = prompt.check(user_prompt, rf_policy)
    if decision.blocked:
        raise HTTPException(403, decision.reason_code)
"""

from diri_agent_guardrails.renderflow.config import RateLimiter, RenderFlowPolicy
from diri_agent_guardrails.renderflow.presets import AVAILABLE_PRESETS, build_policy, get_preset
from diri_agent_guardrails.renderflow.types import GuardrailDecision, ReasonCode, Verdict

__all__ = [
    "AVAILABLE_PRESETS",
    "GuardrailDecision",
    "RateLimiter",
    "RenderFlowPolicy",
    "ReasonCode",
    "Verdict",
    "build_policy",
    "get_preset",
]
