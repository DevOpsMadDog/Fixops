"""Evidence export bundle builder for Part 3 alignment."""

from __future__ import annotations

import base64
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, Tuple
from zipfile import ZIP_DEFLATED, ZipFile

import structlog

try:
    from core.services.enterprise.evidence_lake import EvidenceLake
except (
    ModuleNotFoundError
):  # pragma: no cover - optional dependency for lightweight tests
    EvidenceLake = None  # type: ignore[assignment]

from core.utils.enterprise.crypto import rsa_sign

logger = structlog.get_logger()


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _render_pdf_summary(record: Dict[str, Any]) -> bytes:
    """Render a minimal, printable PDF summarising the evidence."""

    lines = [
        f"Evidence ID: {record.get('evidence_id', 'unknown')}",
        f"Tenant: {record.get('tenant', 'n/a')}",
        f"Decision: {record.get('decision', 'n/a')}",
        f"Confidence: {record.get('confidence_score', 'n/a')}",
        f"Generated: {record.get('stored_timestamp', datetime.now(timezone.utc).isoformat())}",
    ]
    lines.append("-- Context Sources --")
    for source in record.get("context_sources", []):
        lines.append(f" * {source}")

    text_commands = ["BT", "/F1 10 Tf", "50 780 Td"]
    first = True
    for line in lines:
        escaped = _escape_pdf_text(str(line))
        if first:
            text_commands.append(f"({escaped}) Tj")
            first = False
        else:
            text_commands.append("T*")
            text_commands.append(f"({escaped}) Tj")
    text_commands.append("ET")

    stream = "\n".join(text_commands)
    stream_bytes = stream.encode("latin-1")

    objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
        f"4 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n{stream}\nendstream\nendobj\n",
        "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj.encode("latin-1"))

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects)+1}\n".encode("latin-1"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010} 00000 n \n".encode("latin-1"))
    pdf.extend(b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n")
    pdf.extend(str(xref_offset).encode("latin-1"))
    pdf.extend(b"\n%%EOF")
    return bytes(pdf)


class EvidenceExportService:
    """Create signed JSON + PDF evidence bundles."""

    async def build_bundle(self, evidence_id: str) -> Tuple[bytes, Dict[str, Any]]:
        if EvidenceLake is None:
            raise RuntimeError(
                "EvidenceLake is unavailable; install pydantic-settings for full support"
            )

        record = await EvidenceLake.retrieve_evidence(evidence_id)
        if record is None:
            raise FileNotFoundError(f"Evidence {evidence_id} not found")

        canonical_json = json.dumps(record, indent=2, sort_keys=True).encode("utf-8")
        signature_bytes, fingerprint = rsa_sign(canonical_json)
        signature_b64 = base64.b64encode(signature_bytes).decode()

        signed_payload = {
            "evidence": record,
            "signature": signature_b64,
            "fingerprint": fingerprint,
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }

        pdf_bytes = _render_pdf_summary(record)

        buffer = io.BytesIO()
        with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
            archive.writestr("evidence.json", canonical_json)
            archive.writestr(
                "evidence.signed.json",
                json.dumps(signed_payload, indent=2).encode("utf-8"),
            )
            archive.writestr("evidence.pdf", pdf_bytes)

        metadata = {
            "evidence_id": evidence_id,
            "fingerprint": fingerprint,
            "signature": signature_b64,
            "files": ["evidence.json", "evidence.signed.json", "evidence.pdf"],
        }
        logger.info(
            "Evidence bundle created", evidence_id=evidence_id, fingerprint=fingerprint
        )
        return buffer.getvalue(), metadata


__all__ = ["EvidenceExportService"]
