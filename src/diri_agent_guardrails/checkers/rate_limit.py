"""Rate-limit checker with injectable backend.

Consolidates rate-limiting logic previously found in advanced.py and
renderflow/gates/policy.py.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from diri_agent_guardrails.core.result import CheckResult
from diri_agent_guardrails.core.verdict import ReasonCode, Verdict


@runtime_checkable
class RateLimitBackend(Protocol):
    def check_and_increment(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        ...


class InMemoryRateLimitBackend:
    """Thread-safe in-memory rate-limit store."""

    def __init__(self) -> None:
        self._store: dict[str, dict] = {}

    def check_and_increment(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        now = datetime.now(timezone.utc)
        if key not in self._store:
            self._store[key] = {"count": 0, "window_start": now}

        info = self._store[key]
        if (now - info["window_start"]).total_seconds() > window_seconds:
            info["count"] = 0
            info["window_start"] = now

        info["count"] += 1
        within_limit = info["count"] <= limit
        return within_limit, info["count"]


class RateLimitChecker:
    """Check whether an action has exceeded its rate limit.

    Parameters
    ----------
    backend
        Rate-limit store. Defaults to ``InMemoryRateLimitBackend``.
        Pass a Redis-backed implementation for production use.
    """

    def __init__(self, backend: RateLimitBackend | None = None) -> None:
        self._backend = backend or InMemoryRateLimitBackend()

    def check(
        self,
        key: str,
        limit: int = 100,
        window_seconds: int = 60,
        **context: Any,
    ) -> CheckResult:
        within_limit, count = self._backend.check_and_increment(key, limit, window_seconds)
        if not within_limit:
            return CheckResult(
                passed=False,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.RATE_LIMITED,
                score=0.8,
                message=f"Rate limit exceeded: {count}/{limit} in {window_seconds}s",
                details={"count": count, "limit": limit, "window_seconds": window_seconds},
            )
        return CheckResult(
            passed=True,
            verdict=Verdict.ALLOW,
            message="Rate limit OK",
            details={"remaining": limit - count},
        )
