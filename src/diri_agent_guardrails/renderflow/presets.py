"""Dynamic policy presets for different deployment contexts.

Usage::

    from diri_agent_guardrails.renderflow.presets import build_policy

    policy = build_policy("eu", user_id="u123", project_id="p456")
"""
from __future__ import annotations

from diri_agent_guardrails.renderflow.config import RenderFlowPolicy

# Each entry is a set of field overrides applied on top of RenderFlowPolicy defaults.
_PRESETS: dict[str, dict] = {
    # Local dev / CI — permissive, no rate limits, no review gate
    "dev": {
        "nsfw_mode": "off",
        "likeness_mode": "off",
        "copyright_mode": "off",
        "rate_limit_per_hour": 1000,
        "require_review": False,
        "region_policy": "dev",
    },
    # Standard US SaaS default
    "us_default": {
        "nsfw_mode": "block",
        "likeness_mode": "strict",
        "copyright_mode": "warn",
        "rate_limit_per_hour": 20,
        "require_review": True,
        "region_policy": "us_default",
    },
    # EU — stricter copyright, C2PA provenance for AI Act Art. 50
    "eu": {
        "nsfw_mode": "block",
        "likeness_mode": "strict",
        "copyright_mode": "block",
        "rate_limit_per_hour": 20,
        "require_review": True,
        "region_policy": "eu",
        "provenance_mode": "c2pa",
    },
    # Enterprise / high-risk — consent-only likeness, local inference, short clips
    "strict": {
        "nsfw_mode": "block",
        "likeness_mode": "consent",
        "copyright_mode": "block",
        "rate_limit_per_hour": 10,
        "require_review": True,
        "cloud_allowed": False,
        "max_duration_sec": 60,
        "provenance_mode": "c2pa",
        "region_policy": "strict",
    },
}

AVAILABLE_PRESETS = list(_PRESETS.keys())


def get_preset(name: str = "us_default") -> RenderFlowPolicy:
    """Return a fresh RenderFlowPolicy for the named preset."""
    overrides = _PRESETS.get(name, _PRESETS["us_default"])
    policy = RenderFlowPolicy()
    for k, v in overrides.items():
        setattr(policy, k, v)
    return policy


def build_policy(preset: str = "us_default", **overrides: object) -> RenderFlowPolicy:
    """Build from a named preset then apply per-request field overrides.

    Example::

        policy = build_policy("us_default", user_id="u1", project_id="p1", user_role="editor")
    """
    policy = get_preset(preset)
    for k, v in overrides.items():
        setattr(policy, k, v)
    return policy
