"""Layer 4 — Output guard.

Runs after all generation stages complete, before JobStatus → REVIEW.

Checks:
  - Frame sample scan (NSFW / violence) — stub, see TODO
  - Likeness / impersonation — stub
  - CSAM hash matching — stub (requires org legal sign-off + licensed hash DB)
  - Copyright signal — per policy.copyright_mode
  - Provenance sidecar build (C2PA or JSON)

Returns (GuardrailDecision, provenance_sidecar_dict).
The caller embeds the sidecar into the output MP4 metadata.
"""
from __future__ import annotations

from datetime import datetime, timezone

from diri_agent_guardrails.renderflow.config import RenderFlowPolicy
from diri_agent_guardrails.renderflow.types import GuardrailDecision, ReasonCode, Verdict

GATE = "output"


def check(
    policy: RenderFlowPolicy,
    *,
    job_id: str,
    model_ids: list[str] | None = None,
    frame_samples: list[bytes] | None = None,
    has_likeness_match: bool = False,
    copyright_similarity_score: float = 0.0,
) -> tuple[GuardrailDecision, dict]:
    """Run all Layer 4 output checks.

    Returns:
        (GuardrailDecision, provenance_sidecar)
        Sidecar is empty dict when provenance_mode == "off".
    """
    # Frame scan stub
    if frame_samples and policy.nsfw_mode != "off":
        for i, frame in enumerate(frame_samples):
            # TODO: plug in image classifier (same as runtime gate)
            # result = _classify_frame(frame)
            # if result.nsfw and policy.nsfw_mode == "block":
            #     return GuardrailDecision(
            #         gate=GATE, verdict=Verdict.BLOCK,
            #         reason_code=ReasonCode.OUTPUT_BLOCK, score=result.score,
            #         details={"frame_index": i},
            #     ), {}
            _ = frame  # suppress unused warning until classifier is wired

    # Likeness / impersonation check
    if has_likeness_match:
        if policy.likeness_mode == "strict":
            return GuardrailDecision(
                gate=GATE,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.LIKENESS_BLOCK,
            ), {}
        if policy.likeness_mode == "consent":
            return GuardrailDecision(
                gate=GATE,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.CONSENT_REQUIRED,
            ), {}

    # CSAM hash stub — never DIY; requires Thorn Safer / PhotoDNA license
    if policy.csam_hash_check:
        # TODO: call licensed hash matching service
        # match = _csam_hash_check(frame_samples or [])
        # if match:
        #     return GuardrailDecision(gate=GATE, verdict=Verdict.BLOCK,
        #         reason_code=ReasonCode.SAFETY_BLOCK, score=1.0,
        #         details={"csam_suspect": True}), {}
        pass

    # Copyright signal
    if copyright_similarity_score > 0.8 and policy.copyright_mode == "block":
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.OUTPUT_BLOCK,
            score=copyright_similarity_score,
            details={"copyright_similarity": copyright_similarity_score},
        ), {}

    if copyright_similarity_score > 0.6 and policy.copyright_mode == "warn":
        provenance = _build_provenance(job_id, model_ids or [], policy)
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.ESCALATE,
            reason_code=ReasonCode.COPYRIGHT_WARN,
            score=copyright_similarity_score,
        ), provenance

    provenance = _build_provenance(job_id, model_ids or [], policy)
    return GuardrailDecision(gate=GATE, verdict=Verdict.ALLOW), provenance


def _build_provenance(
    job_id: str, model_ids: list[str], policy: RenderFlowPolicy
) -> dict:
    if policy.provenance_mode == "off":
        return {}
    return {
        "schema": "c2pa-lite-v1" if policy.provenance_mode == "c2pa" else "renderflow-sidecar-v1",
        "generator": "Deepiri RenderFlow RFIR",
        "job_id": job_id,
        "model_ids": model_ids,
        "ai_generated": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
