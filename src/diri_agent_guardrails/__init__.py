"""
diri-agent-guardrails — reusable safety checks for AI agents.

Submodules:

- ``safety`` — classic ``SafetyGuardrails`` (sync)
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
    "EnhancedGuardrails",
    "GuardrailAction",
    "GuardrailCategory",
    "GuardrailPolicy",
    "GuardrailResult",
    "GuardrailRule",
    "RiskLevel",
    "SafetyCheckResult",
    "SafetyGuardrails",
    "SafetyLevel",
    "get_advanced_guardrails",
    "get_enhanced_guardrails",
    "get_guardrails",
    "reload_guardrails",
    "reset_enhanced_guardrails",
]

__version__ = "0.1.0"
