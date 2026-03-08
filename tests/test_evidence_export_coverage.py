"""Tests for evidence export — PDF rendering, text escaping."""

from core.services.enterprise.evidence_export import (
    _escape_pdf_text,
    _render_pdf_summary,
)


class TestEscapePdfText:
    def test_no_special_chars(self):
        assert _escape_pdf_text("hello world") == "hello world"

    def test_backslash(self):
        assert _escape_pdf_text("path\\file") == "path\\\\file"

    def test_parens(self):
        assert _escape_pdf_text("(text)") == "\\(text\\)"

    def test_combined(self):
        result = _escape_pdf_text("(test\\path)")
        assert result == "\\(test\\\\path\\)"

    def test_empty_string(self):
        assert _escape_pdf_text("") == ""


class TestRenderPdfSummary:
    def test_basic_record(self):
        record = {
            "evidence_id": "ev-001",
            "tenant": "acme",
            "decision": "ALLOW",
            "confidence_score": 0.95,
            "context_sources": ["scanner", "feeds"],
        }
        pdf_bytes = _render_pdf_summary(record)
        assert isinstance(pdf_bytes, (bytes, bytearray))
        assert pdf_bytes[:5] == b"%PDF-"
        assert b"%%EOF" in pdf_bytes

    def test_empty_record(self):
        pdf_bytes = _render_pdf_summary({})
        assert isinstance(pdf_bytes, (bytes, bytearray))
        assert pdf_bytes[:5] == b"%PDF-"

    def test_record_with_special_chars(self):
        record = {
            "evidence_id": "ev-(special)",
            "tenant": "org\\team",
            "decision": "BLOCK",
            "confidence_score": 0.5,
            "context_sources": [],
        }
        pdf_bytes = _render_pdf_summary(record)
        assert isinstance(pdf_bytes, (bytes, bytearray))

    def test_pdf_contains_evidence_id(self):
        record = {
            "evidence_id": "ev-unique-42",
            "context_sources": [],
        }
        pdf_bytes = _render_pdf_summary(record)
        assert b"ev-unique-42" in pdf_bytes

    def test_pdf_contains_context_sources(self):
        record = {
            "evidence_id": "ev-003",
            "context_sources": ["nvd", "epss", "kev"],
        }
        pdf_bytes = _render_pdf_summary(record)
        assert b"nvd" in pdf_bytes
        assert b"epss" in pdf_bytes
        assert b"kev" in pdf_bytes

    def test_large_record(self):
        record = {
            "evidence_id": "ev-large",
            "tenant": "big-org",
            "decision": "DEFER",
            "confidence_score": 0.42,
            "context_sources": [f"source-{i}" for i in range(20)],
        }
        pdf_bytes = _render_pdf_summary(record)
        assert len(pdf_bytes) > 100
