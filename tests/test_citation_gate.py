"""Tests for citation gate and persona scope checkers."""

from diri_agent_guardrails.checkers.citation_gate import CitationGateChecker, PersonaScopeChecker
from diri_agent_guardrails.core.verdict import ReasonCode, Verdict


class TestCitationGateChecker:
    def test_allows_confession_without_spans(self):
        checker = CitationGateChecker()
        result = checker.check(
            "I cannot answer",
            confessed=True,
            hard_citation_gate=True,
            spans=[],
        )
        assert result.passed is True

    def test_blocks_empty_spans_when_not_confessed(self):
        checker = CitationGateChecker()
        result = checker.check(
            "The rent is $4500",
            confessed=False,
            hard_citation_gate=True,
            spans=[],
        )
        assert result.verdict == Verdict.BLOCK
        assert result.reason_code == ReasonCode.CITATION_GATE_FAILED

    def test_allows_verbatim_witness(self):
        checker = CitationGateChecker()
        quote = "The base rent shall be $4,500 per month."
        result = checker.check(
            quote,
            confessed=False,
            hard_citation_gate=True,
            spans=[{"quote": quote}],
            question="What is base rent?",
        )
        assert result.passed is True


class TestPersonaScopeChecker:
    def test_blocks_out_of_corpus_document(self):
        checker = PersonaScopeChecker()
        result = checker.check(
            "question",
            document_id="doc_b",
            corpus_filter=["doc_a"],
        )
        assert result.verdict == Verdict.BLOCK
        assert result.reason_code == ReasonCode.PERSONA_SCOPE_VIOLATION

    def test_allows_in_corpus_document(self):
        checker = PersonaScopeChecker()
        result = checker.check(
            "question",
            document_id="doc_a",
            corpus_filter=["doc_a"],
        )
        assert result.passed is True
