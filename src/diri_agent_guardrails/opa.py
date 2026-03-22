"""
Optional Open Policy Agent (OPA) integration via REST API.

Install with: ``pip install diri-agent-guardrails[opa]``
"""
from __future__ import annotations

from typing import Any, Dict, Optional

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[misc, assignment]


class OPAUnavailableError(RuntimeError):
    """Raised when OPA helpers are used without httpx installed."""


async def evaluate_opa(
    *,
    input_data: Dict[str, Any],
    policy_path: str = "agent/guardrails/allow",
    opa_url: str = "http://127.0.0.1:8181",
    client: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    POST ``input`` to OPA's Data API and return the JSON body.

    ``policy_path`` is the relative path under ``/v1/data/`` (no leading slash).

    Example policy package (Rego)::

        package agent.guardrails

        default allow := false
        allow if { input.user.role == "admin" }
    """
    if httpx is None:
        raise OPAUnavailableError(
            "OPA integration requires httpx. Install: pip install diri-agent-guardrails[opa]"
        )

    url = f"{opa_url.rstrip('/')}/v1/data/{policy_path.lstrip('/')}"
    use_client = client or httpx.AsyncClient(timeout=30.0)
    close = client is None
    try:
        resp = await use_client.post(url, json={"input": input_data})
        resp.raise_for_status()
        return resp.json()
    finally:
        if close:
            await use_client.aclose()
