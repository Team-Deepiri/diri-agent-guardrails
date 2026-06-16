"""Tests for renderflow types and presets."""
import pytest

from diri_agent_guardrails.renderflow.types import GuardrailDecision, ReasonCode, Verdict
from diri_agent_guardrails.renderflow.presets import build_policy, get_preset, AVAILABLE_PRESETS


def test_verdict_blocked_property():
    d = GuardrailDecision(gate="policy", verdict=Verdict.BLOCK, reason_code=ReasonCode.AI_DISABLED)
    assert d.blocked is True


def test_verdict_allow_not_blocked():
    d = GuardrailDecision(gate="policy", verdict=Verdict.ALLOW)
    assert d.blocked is False


def test_to_dict_shape():
    d = GuardrailDecision(
        gate="prompt",
        verdict=Verdict.BLOCK,
        reason_code=ReasonCode.SAFETY_BLOCK,
        score=0.95,
        details={"zero_tolerance": True},
    )
    out = d.to_dict()
    assert out["gate"] == "prompt"
    assert out["verdict"] == "block"
    assert out["reason_code"] == "SAFETY_BLOCK"
    assert out["score"] == 0.95


def test_to_dict_no_reason_code():
    d = GuardrailDecision(gate="policy", verdict=Verdict.ALLOW)
    assert d.to_dict()["reason_code"] is None


@pytest.mark.parametrize("preset", AVAILABLE_PRESETS)
def test_all_presets_build(preset):
    policy = get_preset(preset)
    assert policy.enabled is True
    assert isinstance(policy.allowed_modes, list)


def test_build_policy_overrides():
    policy = build_policy("us_default", user_id="u42", project_id="p99", user_role="admin")
    assert policy.user_id == "u42"
    assert policy.project_id == "p99"
    assert policy.user_role == "admin"
    assert policy.nsfw_mode == "block"  # from preset


def test_dev_preset_permissive():
    policy = get_preset("dev")
    assert policy.nsfw_mode == "off"
    assert policy.require_review is False
    assert policy.rate_limit_per_hour == 1000


def test_eu_preset_c2pa():
    policy = get_preset("eu")
    assert policy.provenance_mode == "c2pa"
    assert policy.copyright_mode == "block"


def test_strict_preset_no_cloud():
    policy = get_preset("strict")
    assert policy.cloud_allowed is False
    assert policy.likeness_mode == "consent"
