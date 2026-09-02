"""Citation gate — Cyrex Voice of the Document hard witness enforcement."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from diri_agent_guardrails.core.result import CheckResult
from diri_agent_guardrails.core.verdict import ReasonCode, Verdict


def _normalize_quote(quote: str) -> str:
    return " ".join(quote.lower().split())


class CitationGateChecker:
    """Block synthesized answers when no witness span supports the claim.

    Context keys (all optional except when enforcing output):
      - ``question``: user question text
      - ``spans``: iterable of witness dicts with ``quote`` keys
      - ``hard_citation_gate``: bool (default True)
      - ``confessed``: bool — when True, gate allows empty spans
    """

    def check(self, text: str, **context: Any) -> CheckResult:
        hard_gate = bool(context.get("hard_citation_gate", True))
        if not hard_gate:
            return CheckResult()

        confessed = bool(context.get("confessed", False))
        spans: Sequence[Mapping[str, Any]] = context.get("spans") or []
        if confessed:
            return CheckResult(
                passed=True,
                verdict=Verdict.ALLOW,
                message="Confession path — no witness span required",
                details={"confessed": True},
            )

        if not spans:
            return CheckResult(
                passed=False,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.CITATION_GATE_FAILED,
                score=1.0,
                message="Hard citation gate: no witness spans returned",
                details={"question": context.get("question", text)},
            )

        question = str(context.get("question") or text)
        quotes = [_normalize_quote(str(s.get("quote", ""))) for s in spans if s.get("quote")]
        if not quotes:
            return CheckResult(
                passed=False,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.WITNESS_SET_VIOLATION,
                score=1.0,
                message="Witness set empty after citation gate",
            )

        # Output text must be composed only of verbatim quotes (no paraphrase).
        output_norm = _normalize_quote(text)
        if output_norm and not any(q in output_norm or output_norm in q for q in quotes if q):
            return CheckResult(
                passed=False,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.WITNESS_SET_VIOLATION,
                score=0.9,
                message="Response text is not a verbatim witness quote",
                details={"quotes": quotes[:3]},
            )

        return CheckResult(
            passed=True,
            verdict=Verdict.ALLOW,
            message="Witness span satisfies citation gate",
            details={"span_count": len(spans)},
        )


class PersonaScopeChecker:
    """Enforce corpus filter and witness-set-only policy on voice queries."""

    def check(self, text: str, **context: Any) -> CheckResult:
        document_id = context.get("document_id")
        corpus_filter: Iterable[str] = context.get("corpus_filter") or []
        corpus_list = list(corpus_filter)
        if corpus_list and document_id and str(document_id) not in corpus_list:
            return CheckResult(
                passed=False,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.PERSONA_SCOPE_VIOLATION,
                score=1.0,
                message="Document not in persona corpus_filter",
                details={"document_id": document_id, "corpus_filter": corpus_list},
            )

        if context.get("witness_set_only") and context.get("allow_synthesis"):
            return CheckResult(
                passed=False,
                verdict=Verdict.BLOCK,
                reason_code=ReasonCode.PERSONA_SCOPE_VIOLATION,
                score=0.95,
                message="witness_set_only forbids synthesized answers",
            )

        return CheckResult()
