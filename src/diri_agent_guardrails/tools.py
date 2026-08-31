"""Tool-side security: permissions, sandbox attestation, least privilege, HITL, audit.

This is the intake-item-4 checklist that ``SafetyGuardrails`` / ``AdvancedGuardrails``
do not cover — those modules check *text*. This module gates *tool execution*.

Callers (Cyrex, toolbox ``ToolRunner``, MCP) should ``authorize`` before invoking a
tool and refuse to run on anything other than ``Verdict.ALLOW``.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Protocol

from diri_agent_guardrails.core.result import CheckResult
from diri_agent_guardrails.core.verdict import ReasonCode, Verdict

logger = logging.getLogger(__name__)

# Parameter names that are treated as filesystem paths for sandbox escape checks.
_PATH_PARAM_KEYS = frozenset({"path", "relative_path", "filename", "file", "dest", "src"})

# Arguments that look like SSRF / shell / SQL payload regardless of the tool name.
_DANGEROUS_ARGUMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"file://", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"169\.254\.169\.254"),
    re.compile(r"metadata\.google\.internal", re.IGNORECASE),
    re.compile(r";\s*(?:rm|del|drop|delete)\b", re.IGNORECASE),
    re.compile(r"\.\.[\\/]"),
)


class ToolRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ToolPermission:
    """Least-privilege grant for a single named tool."""

    name: str
    risk: ToolRisk = ToolRisk.LOW
    denied: bool = False
    requires_sandbox: bool = False
    requires_approval: bool = False
    scopes: frozenset[str] = field(default_factory=frozenset)
    allowed_param_keys: frozenset[str] | None = None


@dataclass(frozen=True)
class ToolCallRequest:
    """What the agent wants to invoke, plus the host's attestations."""

    tool_name: str
    parameters: dict[str, Any] = field(default_factory=dict)
    agent_id: str | None = None
    # Scopes the *caller* currently holds (not the tool's required set).
    scopes: frozenset[str] = field(default_factory=frozenset)
    # Host attests the implementation is sandboxed (e.g. SandboxedFileToolbox).
    sandboxed: bool = False
    sandbox_root: str | Path | None = None
    # Host attests a human already approved this exact call.
    approved: bool = False


@dataclass(frozen=True)
class ToolAuditEvent:
    tool_name: str
    verdict: Verdict
    reason_code: ReasonCode | None
    agent_id: str | None
    message: str
    timestamp: datetime
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "verdict": self.verdict.value,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "agent_id": self.agent_id,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }


class AuditSink(Protocol):
    def emit(self, event: ToolAuditEvent) -> None: ...


class InMemoryAuditLog:
    """Default monitor: keep every authorize decision for inspection / tests."""

    def __init__(self) -> None:
        self.events: list[ToolAuditEvent] = []

    def emit(self, event: ToolAuditEvent) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()


class ToolPolicy:
    """Deny-by-default catalog of tool permissions."""

    def __init__(
        self,
        permissions: Iterable[ToolPermission],
        *,
        default_deny: bool = True,
    ) -> None:
        self._permissions = {p.name: p for p in permissions}
        self.default_deny = default_deny

    def get(self, name: str) -> ToolPermission | None:
        return self._permissions.get(name)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._permissions)


def default_tool_policy() -> ToolPolicy:
    """Catalog aligned with ``diri-agent-toolbox`` plus known-dangerous names.

    Unknown tools are denied. Shell/DB-destroy names are present so a
    misconfigured ``default_deny=False`` host still blocks them.
    """
    low_data = (
        "json_parse",
        "json_format",
        "data_transform",
        "calculate",
        "statistics",
        "text_summarize",
        "text_extract",
        "current_time",
    )
    permissions: list[ToolPermission] = [
        ToolPermission(name=n, risk=ToolRisk.LOW) for n in low_data
    ]
    permissions.extend(
        [
            ToolPermission(
                name="file_read",
                risk=ToolRisk.MEDIUM,
                requires_sandbox=True,
                scopes=frozenset({"files:read"}),
                allowed_param_keys=frozenset({"relative_path", "path", "encoding"}),
            ),
            ToolPermission(
                name="file_list_dir",
                risk=ToolRisk.MEDIUM,
                requires_sandbox=True,
                scopes=frozenset({"files:read"}),
                allowed_param_keys=frozenset({"relative_path", "path"}),
            ),
            ToolPermission(
                name="file_stat",
                risk=ToolRisk.MEDIUM,
                requires_sandbox=True,
                scopes=frozenset({"files:read"}),
                allowed_param_keys=frozenset({"relative_path", "path"}),
            ),
            ToolPermission(
                name="file_write",
                risk=ToolRisk.HIGH,
                requires_sandbox=True,
                requires_approval=True,
                scopes=frozenset({"files:write"}),
                allowed_param_keys=frozenset({"relative_path", "path", "content", "encoding"}),
            ),
            ToolPermission(
                name="http_get",
                risk=ToolRisk.HIGH,
                scopes=frozenset({"http"}),
                allowed_param_keys=frozenset({"url", "headers", "query_params", "timeout"}),
            ),
            ToolPermission(
                name="http_post",
                risk=ToolRisk.HIGH,
                requires_approval=True,
                scopes=frozenset({"http"}),
                allowed_param_keys=frozenset(
                    {"url", "headers", "query_params", "json_body", "timeout"}
                ),
            ),
            ToolPermission(
                name="http_request",
                risk=ToolRisk.HIGH,
                requires_approval=True,
                scopes=frozenset({"http"}),
            ),
            ToolPermission(
                name="calendar_list_events",
                risk=ToolRisk.MEDIUM,
                scopes=frozenset({"calendar:read"}),
            ),
            ToolPermission(
                name="calendar_create_event",
                risk=ToolRisk.HIGH,
                requires_approval=True,
                scopes=frozenset({"calendar:write"}),
            ),
            ToolPermission(
                name="crm_request",
                risk=ToolRisk.HIGH,
                requires_approval=True,
                scopes=frozenset({"crm"}),
            ),
            ToolPermission(
                name="db_query",
                risk=ToolRisk.HIGH,
                requires_approval=True,
                scopes=frozenset({"db:read"}),
            ),
            ToolPermission(
                name="db_execute",
                risk=ToolRisk.CRITICAL,
                requires_approval=True,
                scopes=frozenset({"db:write"}),
            ),
        ]
    )
    for banned in (
        "execute_shell",
        "run_command",
        "delete_database",
        "drop_table",
        "rm_rf",
        "eval",
        "exec",
    ):
        permissions.append(
            ToolPermission(name=banned, risk=ToolRisk.CRITICAL, denied=True)
        )
    return ToolPolicy(permissions, default_deny=True)


class ToolGate:
    """Authorize a tool call. Does not execute the tool."""

    def __init__(
        self,
        policy: ToolPolicy | None = None,
        *,
        audit: AuditSink | None = None,
    ) -> None:
        self.policy = policy or default_tool_policy()
        self.audit = audit if audit is not None else InMemoryAuditLog()

    def authorize(self, request: ToolCallRequest) -> CheckResult:
        result = self._evaluate(request)
        event = ToolAuditEvent(
            tool_name=request.tool_name,
            verdict=result.verdict,
            reason_code=result.reason_code,
            agent_id=request.agent_id,
            message=result.message,
            timestamp=result.timestamp,
            details=dict(result.details),
        )
        try:
            self.audit.emit(event)
        except Exception:
            logger.exception("tool-gate audit sink failed")
        if not result.passed:
            logger.warning(
                "tool denied name=%s verdict=%s reason=%s agent=%s",
                request.tool_name,
                result.verdict.value,
                result.reason_code.value if result.reason_code else None,
                request.agent_id,
            )
        return result

    def _evaluate(self, request: ToolCallRequest) -> CheckResult:
        perm = self.policy.get(request.tool_name)
        if perm is None:
            if self.policy.default_deny:
                return _deny(
                    ReasonCode.TOOL_UNKNOWN,
                    f"Unknown tool '{request.tool_name}' is denied by default",
                    tool_name=request.tool_name,
                )
            return _allow(f"Tool '{request.tool_name}' is not in the catalog")

        if perm.denied:
            return _deny(
                ReasonCode.TOOL_DENIED,
                f"Tool '{request.tool_name}' is forbidden",
                tool_name=request.tool_name,
                risk=perm.risk.value,
            )

        if perm.scopes and not perm.scopes.issubset(request.scopes):
            missing = sorted(perm.scopes - request.scopes)
            return _deny(
                ReasonCode.TOOL_SCOPE_DENIED,
                f"Tool '{request.tool_name}' requires scopes {sorted(perm.scopes)}",
                tool_name=request.tool_name,
                missing_scopes=missing,
            )

        if perm.allowed_param_keys is not None:
            extra = sorted(set(request.parameters) - perm.allowed_param_keys)
            if extra:
                return _deny(
                    ReasonCode.TOOL_PARAM_DENIED,
                    f"Tool '{request.tool_name}' was called with extra parameters",
                    tool_name=request.tool_name,
                    extra_params=extra,
                )

        if perm.requires_sandbox and not request.sandboxed:
            return _deny(
                ReasonCode.TOOL_NOT_SANDBOXED,
                f"Tool '{request.tool_name}' must run inside a sandbox",
                tool_name=request.tool_name,
            )

        escape = _path_escape(request)
        if escape is not None:
            return escape

        dangerous = _dangerous_arguments(request.parameters)
        if dangerous is not None:
            return dangerous

        if perm.requires_approval and not request.approved:
            return CheckResult(
                passed=False,
                verdict=Verdict.ESCALATE,
                reason_code=ReasonCode.TOOL_NEEDS_APPROVAL,
                score=0.9 if perm.risk in (ToolRisk.HIGH, ToolRisk.CRITICAL) else 0.7,
                message=(
                    f"Tool '{request.tool_name}' is high-risk and needs human approval"
                ),
                details={"tool_name": request.tool_name, "risk": perm.risk.value},
            )

        return _allow(
            f"Tool '{request.tool_name}' authorized",
            tool_name=request.tool_name,
            risk=perm.risk.value,
        )


def path_escapes_sandbox(root: str | Path, relative: str) -> bool:
    """True when ``relative`` would resolve outside ``root``."""
    try:
        base = Path(root).resolve()
        candidate = (base / relative).resolve()
        candidate.relative_to(base)
    except (OSError, ValueError):
        return True
    return False


def _path_escape(request: ToolCallRequest) -> CheckResult | None:
    if request.sandbox_root is None:
        return None
    for key, value in request.parameters.items():
        if key not in _PATH_PARAM_KEYS or not isinstance(value, str):
            continue
        if path_escapes_sandbox(request.sandbox_root, value):
            return _deny(
                ReasonCode.TOOL_PATH_ESCAPE,
                f"Path parameter '{key}' escapes the sandbox",
                tool_name=request.tool_name,
                param=key,
                value=value,
            )
    return None


def _dangerous_arguments(parameters: dict[str, Any]) -> CheckResult | None:
    try:
        blob = json.dumps(parameters, default=str)
    except TypeError:
        blob = str(parameters)
    for pattern in _DANGEROUS_ARGUMENT_PATTERNS:
        match = pattern.search(blob)
        if match:
            return _deny(
                ReasonCode.TOOL_DANGEROUS_ARGUMENT,
                "Dangerous pattern in tool parameters",
                pattern=pattern.pattern,
                match=match.group(),
            )
    return None


def _allow(message: str, **details: Any) -> CheckResult:
    return CheckResult(
        passed=True,
        verdict=Verdict.ALLOW,
        message=message,
        details=details,
        timestamp=datetime.now(timezone.utc),
    )


def _deny(reason: ReasonCode, message: str, **details: Any) -> CheckResult:
    return CheckResult(
        passed=False,
        verdict=Verdict.BLOCK,
        reason_code=reason,
        score=1.0,
        message=message,
        details=details,
        timestamp=datetime.now(timezone.utc),
    )
