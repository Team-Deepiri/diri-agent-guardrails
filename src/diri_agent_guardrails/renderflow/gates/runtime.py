"""Layer 3 — Generation / runtime guard (model-worker side).

Called between RFIR IR node executions during a running job.
Currently a stub — wire a real image classifier to replace the TODO.

The interface is intentionally simple: caller passes raw frame bytes and gets
a GuardrailDecision. Worker aborts the job on any BLOCK verdict and must NOT
persist the offending keyframe to long-term storage.

To integrate a real NSFW/violence classifier (e.g. Falconsai/nsfw_image_detection):

    from diri_agent_guardrails.renderflow.gates.runtime import check_keyframe
    decision = check_keyframe(frame_bytes, policy, frame_index=i)
    if decision.blocked:
        # discard tensors, abort job
"""
from __future__ import annotations

from diri_agent_guardrails.renderflow.config import RenderFlowPolicy
from diri_agent_guardrails.renderflow.types import GuardrailDecision, ReasonCode, Verdict

GATE = "generation"


def check_keyframe(
    frame_bytes: bytes,
    policy: RenderFlowPolicy,
    *,
    frame_index: int = 0,
) -> GuardrailDecision:
    """Scan a single decoded keyframe for policy violations.

    Stub implementation — always returns ALLOW.
    Replace the TODO block with a real image classifier call.
    """
    if policy.nsfw_mode != "off":
        # TODO: plug in real image classifier
        # Example (transformers):
        #   from PIL import Image
        #   import io, torch
        #   from transformers import pipeline
        #   clf = pipeline("image-classification", model="Falconsai/nsfw_image_detection")
        #   img = Image.open(io.BytesIO(frame_bytes))
        #   scores = {r["label"]: r["score"] for r in clf(img)}
        #   if scores.get("nsfw", 0) > 0.7:
        #       return GuardrailDecision(
        #           gate=GATE, verdict=Verdict.BLOCK,
        #           reason_code=ReasonCode.OUTPUT_BLOCK,
        #           score=scores["nsfw"],
        #           details={"frame_index": frame_index},
        #       )
        pass

    return GuardrailDecision(
        gate=GATE,
        verdict=Verdict.ALLOW,
        details={"frame_index": frame_index, "frame_size_bytes": len(frame_bytes)},
    )


def check_budget(elapsed_gpu_sec: float, policy: RenderFlowPolicy) -> GuardrailDecision:
    """Check whether the job has exceeded its GPU time budget."""
    if policy.max_gpu_seconds is not None and elapsed_gpu_sec > policy.max_gpu_seconds:
        return GuardrailDecision(
            gate=GATE,
            verdict=Verdict.BLOCK,
            reason_code=ReasonCode.QUOTA_EXCEEDED,
            details={
                "elapsed_sec": elapsed_gpu_sec,
                "limit_sec": policy.max_gpu_seconds,
            },
        )
    return GuardrailDecision(gate=GATE, verdict=Verdict.ALLOW)
