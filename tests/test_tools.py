from pathlib import Path

from diri_agent_guardrails.core.verdict import ReasonCode, Verdict
from diri_agent_guardrails.tools import (
    InMemoryAuditLog,
    ToolCallRequest,
    ToolGate,
    ToolPermission,
    ToolPolicy,
    ToolRisk,
    default_tool_policy,
    path_escapes_sandbox,
)


def test_unknown_tool_denied_by_default() -> None:
    gate = ToolGate()
    result = gate.authorize(ToolCallRequest(tool_name="not_a_real_tool"))
    assert result.passed is False
    assert result.verdict == Verdict.BLOCK
    assert result.reason_code == ReasonCode.TOOL_UNKNOWN


def test_calculate_allowed() -> None:
    gate = ToolGate()
    result = gate.authorize(
        ToolCallRequest(tool_name="calculate", parameters={"expression": "1+1"})
    )
    assert result.passed is True
    assert result.verdict == Verdict.ALLOW


def test_execute_shell_forbidden() -> None:
    gate = ToolGate()
    result = gate.authorize(
        ToolCallRequest(tool_name="execute_shell", parameters={"cmd": "ls"})
    )
    assert result.reason_code == ReasonCode.TOOL_DENIED


def test_file_read_requires_sandbox() -> None:
    gate = ToolGate()
    result = gate.authorize(
        ToolCallRequest(
            tool_name="file_read",
            parameters={"relative_path": "notes.txt"},
            scopes=frozenset({"files:read"}),
        )
    )
    assert result.reason_code == ReasonCode.TOOL_NOT_SANDBOXED


def test_file_read_requires_scope() -> None:
    gate = ToolGate()
    result = gate.authorize(
        ToolCallRequest(
            tool_name="file_read",
            parameters={"relative_path": "notes.txt"},
            sandboxed=True,
        )
    )
    assert result.reason_code == ReasonCode.TOOL_SCOPE_DENIED


def test_file_read_authorized_when_sandboxed_with_scope() -> None:
    gate = ToolGate()
    result = gate.authorize(
        ToolCallRequest(
            tool_name="file_read",
            parameters={"relative_path": "notes.txt"},
            sandboxed=True,
            scopes=frozenset({"files:read"}),
        )
    )
    assert result.passed is True


def test_file_write_needs_human_approval() -> None:
    gate = ToolGate()
    req = ToolCallRequest(
        tool_name="file_write",
        parameters={"relative_path": "out.txt", "content": "hi"},
        sandboxed=True,
        scopes=frozenset({"files:write"}),
    )
    pending = gate.authorize(req)
    assert pending.verdict == Verdict.ESCALATE
    assert pending.reason_code == ReasonCode.TOOL_NEEDS_APPROVAL

    approved = gate.authorize(
        ToolCallRequest(
            tool_name=req.tool_name,
            parameters=req.parameters,
            sandboxed=req.sandboxed,
            scopes=req.scopes,
            approved=True,
        )
    )
    assert approved.passed is True


def test_extra_params_denied() -> None:
    gate = ToolGate()
    result = gate.authorize(
        ToolCallRequest(
            tool_name="file_read",
            parameters={"relative_path": "a.txt", "owner": "root"},
            sandboxed=True,
            scopes=frozenset({"files:read"}),
        )
    )
    assert result.reason_code == ReasonCode.TOOL_PARAM_DENIED


def test_path_escape_blocked_when_root_given(tmp_path: Path) -> None:
    gate = ToolGate()
    result = gate.authorize(
        ToolCallRequest(
            tool_name="file_read",
            parameters={"relative_path": "../../etc/passwd"},
            sandboxed=True,
            sandbox_root=tmp_path,
            scopes=frozenset({"files:read"}),
        )
    )
    assert result.reason_code in (
        ReasonCode.TOOL_PATH_ESCAPE,
        ReasonCode.TOOL_DANGEROUS_ARGUMENT,
    )


def test_path_escapes_sandbox_helper(tmp_path: Path) -> None:
    assert path_escapes_sandbox(tmp_path, "../../etc/passwd") is True
    assert path_escapes_sandbox(tmp_path, "ok.txt") is False


def test_http_post_needs_approval() -> None:
    gate = ToolGate()
    result = gate.authorize(
        ToolCallRequest(
            tool_name="http_post",
            parameters={"url": "https://api.example.com/v1"},
            scopes=frozenset({"http"}),
        )
    )
    assert result.verdict == Verdict.ESCALATE


def test_audit_log_records_every_decision() -> None:
    log = InMemoryAuditLog()
    gate = ToolGate(audit=log)
    gate.authorize(ToolCallRequest(tool_name="execute_shell"))
    gate.authorize(ToolCallRequest(tool_name="calculate", parameters={"expression": "2"}))
    assert len(log.events) == 2
    assert log.events[0].reason_code == ReasonCode.TOOL_DENIED
    assert log.events[1].verdict == Verdict.ALLOW


def test_explicitly_denied_even_when_default_deny_off() -> None:
    policy = ToolPolicy(
        [ToolPermission(name="execute_shell", denied=True, risk=ToolRisk.CRITICAL)],
        default_deny=False,
    )
    gate = ToolGate(policy)
    result = gate.authorize(ToolCallRequest(tool_name="execute_shell"))
    assert result.reason_code == ReasonCode.TOOL_DENIED
    unknown = gate.authorize(ToolCallRequest(tool_name="custom_ok_tool"))
    assert unknown.passed is True


def test_default_catalog_covers_toolbox_names() -> None:
    names = default_tool_policy().names
    for expected in (
        "json_parse",
        "http_get",
        "file_read",
        "file_write",
        "calendar_create_event",
        "execute_shell",
    ):
        assert expected in names
