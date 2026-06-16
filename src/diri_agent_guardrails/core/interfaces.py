"""Abstract guardrail primitives -- protocols and base classes."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Protocol, runtime_checkable

from diri_agent_guardrails.core.result import CheckResult
from diri_agent_guardrails.core.verdict import Verdict


@runtime_checkable
class GuardrailChecker(Protocol):
    """A single check operation (injection, PII, content safety, etc.)."""

    def check(self, text: str, **context: Any) -> CheckResult:
        ...


class GuardrailPolicy(ABC):
    """Abstract policy that a domain-specific policy (e.g. RenderFlow, ADS-B) implements."""

    @abstractmethod
    def is_enabled(self) -> bool:
        ...

    @abstractmethod
    def action_on_violation(self) -> Verdict:
        ...


class GuardrailEngine:
    """Orchestrates multiple named checkers and returns the most severe result."""

    def __init__(self, checkers: dict[str, GuardrailChecker]) -> None:
        self._checkers = checkers

    @property
    def checkers(self) -> dict[str, GuardrailChecker]:
        return dict(self._checkers)

    def check(self, text: str, **context: Any) -> CheckResult:
        worst: CheckResult | None = None
        for name, checker in self._checkers.items():
            result = checker.check(text, **context)
            if not result.passed:
                result.details["checker"] = name
                if worst is None or _is_more_severe(result, worst):
                    worst = result
        return worst if worst is not None else CheckResult()

    async def async_check(self, text: str, **context: Any) -> CheckResult:
        return self.check(text, **context)

    def add_checker(self, name: str, checker: GuardrailChecker) -> None:
        self._checkers[name] = checker

    def remove_checker(self, name: str) -> None:
        self._checkers.pop(name, None)


_SEVERITY_ORDER = [Verdict.BLOCK, Verdict.REDACT, Verdict.ESCALATE, Verdict.WARN, Verdict.ALLOW]


def _is_more_severe(a: CheckResult, b: CheckResult) -> bool:
    a_order = _SEVERITY_ORDER.index(a.verdict) if a.verdict in _SEVERITY_ORDER else 99
    b_order = _SEVERITY_ORDER.index(b.verdict) if b.verdict in _SEVERITY_ORDER else 99
    if a_order != b_order:
        return a_order < b_order
    return a.score > b.score
