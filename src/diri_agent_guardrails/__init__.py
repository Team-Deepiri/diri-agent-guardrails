"""
diri-agent-guardrails — reusable safety checks for AI agents.

Submodules:

- ``core`` — Domain-agnostic guardrail primitives (interfaces, verdict, result, engine)
- ``checkers`` — Consolidated validators (injection, PII, content, rate-limit, format)
- ``safety`` — Classic ``SafetyGuardrails`` (sync, backward-compat wrapper)
- ``advanced`` — ``AdvancedGuardrails`` with policies (async)
- ``enhanced`` — rule-based ``EnhancedGuardrails`` with optional Postgres
- ``opa`` — optional OPA REST client (requires ``[opa]`` extra)
"""

from diri_agent_guardrails.advanced import (
    AdvancedGuardrails,
    GuardrailAction,
    GuardrailCategory,
    GuardrailPolicy,
    GuardrailResult,
    RiskLevel,
    get_advanced_guardrails,
    reload_guardrails,
)
from diri_agent_guardrails.checkers.citation_gate import CitationGateChecker, PersonaScopeChecker
from diri_agent_guardrails.checkers.content import ContentSafetyChecker
from diri_agent_guardrails.checkers.format import FormatChecker
from diri_agent_guardrails.checkers.injection import InjectionChecker
from diri_agent_guardrails.checkers.pii import PIIChecker
from diri_agent_guardrails.checkers.rate_limit import InMemoryRateLimitBackend, RateLimitChecker
from diri_agent_guardrails.core.interfaces import GuardrailChecker, GuardrailEngine
from diri_agent_guardrails.core.interfaces import GuardrailPolicy as CoreGuardrailPolicy
from diri_agent_guardrails.core.result import CheckResult
from diri_agent_guardrails.core.verdict import ReasonCode, Verdict
from diri_agent_guardrails.enhanced import (
    EnhancedGuardrails,
    GuardrailRule,
    get_enhanced_guardrails,
    reset_enhanced_guardrails,
)
from diri_agent_guardrails.protocols import AsyncPostgresClient
from diri_agent_guardrails.safety import (
    SafetyCheckResult,
    SafetyGuardrails,
    SafetyLevel,
    get_guardrails,
)

__all__ = [
    "AdvancedGuardrails",
    "AsyncPostgresClient",
    "CheckResult",
    "CitationGateChecker",
    "ContentSafetyChecker",
    "CoreGuardrailPolicy",
    "EnhancedGuardrails",
    "FormatChecker",
    "GuardrailAction",
    "GuardrailCategory",
    "GuardrailChecker",
    "GuardrailEngine",
    "GuardrailPolicy",
    "GuardrailResult",
    "GuardrailRule",
    "InMemoryRateLimitBackend",
    "InjectionChecker",
    "PersonaScopeChecker",
    "PIIChecker",
    "RateLimitChecker",
    "ReasonCode",
    "RiskLevel",
    "SafetyCheckResult",
    "SafetyGuardrails",
    "SafetyLevel",
    "Verdict",
    "get_advanced_guardrails",
    "get_enhanced_guardrails",
    "get_guardrails",
    "reload_guardrails",
    "reset_enhanced_guardrails",
]

__version__ = "0.1.1"
