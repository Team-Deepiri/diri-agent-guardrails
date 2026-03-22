"""Protocols for optional integrations (PostgreSQL, etc.)."""
from __future__ import annotations

from typing import Any, List, Protocol, runtime_checkable


@runtime_checkable
class AsyncPostgresClient(Protocol):
    """Minimal async DB surface (e.g. Cyrex PostgreSQLManager)."""

    async def execute(self, query: str, *args: Any) -> Any: ...

    async def fetch(self, query: str, *args: Any) -> List[Any]: ...
