"""Tests for Layer 0 — policy gate."""
import pytest

from diri_agent_guardrails.renderflow.config import RenderFlowPolicy
from diri_agent_guardrails.renderflow.gates.policy import check
from diri_agent_guardrails.renderflow.types import ReasonCode, Verdict


def _policy(**kwargs) -> RenderFlowPolicy:
    return RenderFlowPolicy(**kwargs)


def test_allow_baseline():
    d = check(_policy(), mode="scene")
    assert d.verdict == Verdict.ALLOW


def test_block_ai_disabled():
    d = check(_policy(ai_enabled=False), mode="scene")
    assert d.blocked
    assert d.reason_code == ReasonCode.AI_DISABLED


def test_block_master_switch():
    d = check(_policy(enabled=False), mode="scene")
    assert d.blocked
    assert d.reason_code == ReasonCode.AI_DISABLED


def test_block_viewer_role():
    d = check(_policy(user_role="viewer"), mode="scene")
    assert d.blocked
    assert d.reason_code == ReasonCode.VIEWER_ROLE


def test_block_disallowed_mode():
    d = check(_policy(allowed_modes=["audio"]), mode="scene")
    assert d.blocked
    assert d.reason_code == ReasonCode.DISALLOWED_MODE
    assert "mode" in d.details


def test_allow_matching_mode():
    d = check(_policy(allowed_modes=["scene", "audio"]), mode="audio")
    assert d.verdict == Verdict.ALLOW


def test_block_no_cloud():
    d = check(_policy(cloud_allowed=False, local_only=False), mode="scene")
    assert d.blocked
    assert d.reason_code == ReasonCode.CLOUD_BLOCKED


def test_allow_local_only_cloud_false():
    # local_only=True means we route locally, so cloud_allowed=False is fine
    d = check(_policy(cloud_allowed=False, local_only=True), mode="scene")
    assert d.verdict == Verdict.ALLOW


# --- Rate limiter ---

class _FakeRateLimiter:
    def __init__(self, allow: bool, count: int = 0):
        self._allow = allow
        self._count = count

    def check_and_increment(self, key, limit, window_hours=1):
        return self._allow, self._count


def test_rate_limit_passed():
    p = _policy(user_id="u1", rate_limit_per_hour=20)
    d = check(p, mode="scene", rate_limiter=_FakeRateLimiter(allow=True, count=5))
    assert d.verdict == Verdict.ALLOW


def test_rate_limit_exceeded():
    p = _policy(user_id="u1", rate_limit_per_hour=20)
    d = check(p, mode="scene", rate_limiter=_FakeRateLimiter(allow=False, count=21))
    assert d.blocked
    assert d.reason_code == ReasonCode.RATE_LIMIT
    assert d.details["count"] == 21


def test_no_rate_limiter_skips_check():
    p = _policy(user_id="u1", rate_limit_per_hour=0)
    d = check(p, mode="scene", rate_limiter=None)
    assert d.verdict == Verdict.ALLOW
