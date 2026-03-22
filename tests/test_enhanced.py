import pytest

from diri_agent_guardrails.enhanced import (
    EnhancedGuardrails,
    get_enhanced_guardrails,
    reset_enhanced_guardrails,
)


@pytest.mark.asyncio
async def test_enhanced_in_memory() -> None:
    reset_enhanced_guardrails()
    g = EnhancedGuardrails(postgres=None)
    await g.initialize()
    r = await g.check("hello world")
    assert r["action"] == "allow"


@pytest.mark.asyncio
async def test_enhanced_profanity() -> None:
    reset_enhanced_guardrails()
    g = EnhancedGuardrails(postgres=None)
    await g.initialize()
    r = await g.check("this is fuck bad")
    assert r["action"] == "block"


@pytest.mark.asyncio
async def test_singleton_resets() -> None:
    reset_enhanced_guardrails()
    a = await get_enhanced_guardrails()
    b = await get_enhanced_guardrails()
    assert a is b
