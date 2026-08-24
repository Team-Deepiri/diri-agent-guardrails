"""Factory for Cyrex Voice-of-the-Document guardrail engines."""

from __future__ import annotations

from diri_agent_guardrails.checkers.citation_gate import CitationGateChecker, PersonaScopeChecker
from diri_agent_guardrails.checkers.injection import InjectionChecker
from diri_agent_guardrails.core.interfaces import GuardrailEngine


def build_voice_guardrail_engine() -> GuardrailEngine:
    """Standard engine for artifact voice queries: injection + persona + citation gate."""
    return GuardrailEngine(
        {
            "injection": InjectionChecker(),
            "persona_scope": PersonaScopeChecker(),
            "citation_gate": CitationGateChecker(),
        }
    )
