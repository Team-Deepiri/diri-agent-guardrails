"""RenderFlow guardrail policy config + injectable protocols."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@runtime_checkable
class RateLimiter(Protocol):
    """Inject a concrete implementation (Redis, in-memory, etc.)."""

    def check_and_increment(self, key: str, limit: int, window_hours: int = 1) -> tuple[bool, int]:
        """Return (within_limit, current_count). Must be thread-safe."""
        ...


@dataclass
class RenderFlowPolicy:
    # Master switch
    enabled: bool = True

    # Project / org level
    ai_enabled: bool = True
    user_role: str = "editor"  # viewer | editor | admin

    # Mode gating
    allowed_modes: list[str] = field(default_factory=lambda: ["scene", "audio", "video"])
    max_tier: str = "C"
    max_duration_sec: int = 120

    # Cloud / routing
    cloud_allowed: bool = True
    local_only: bool = False

    # Human review
    require_review: bool = True

    # Content policy knobs (see guardrails spec §4)
    nsfw_mode: str = "block"       # block | restricted | off
    likeness_mode: str = "strict"  # strict | consent | off
    copyright_mode: str = "warn"   # block | warn | off
    region_policy: str = "default"  # default | eu | us_default | strict

    # Rate limiting
    rate_limit_per_hour: int = 20
    user_id: str | None = None
    project_id: str | None = None

    # Budget
    max_gpu_seconds: int | None = None

    # Prompt
    max_prompt_length: int = 4000

    # Opt-in legal features (require explicit org + legal enable)
    csam_hash_check: bool = False

    # Provenance / transparency (EU AI Act)
    provenance_mode: str = "json"  # c2pa | json | off
