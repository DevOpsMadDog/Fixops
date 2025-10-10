"""Utilities for ingesting VEX (Vulnerability Exploitability eXchange) documents.

The DecisionFactory Part 3 scope requires runtime ingestion of supplier VEX
attestations so that `not_affected` components are suppressed automatically.
This module parses SPDX and CycloneDX inputs, persists the resulting
assertions under the cached feeds directory, and exposes helpers for applying
those assertions to enriched security findings.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional

import structlog

logger = structlog.get_logger()

def _resolve_vex_cache() -> Path:
    base = Path(os.getenv("FIXOPS_FEEDS_DIR", "/app/data/feeds"))
    base.mkdir(parents=True, exist_ok=True)
    return base / "vex"


_VEX_CACHE = _resolve_vex_cache()
_VEX_CACHE.mkdir(parents=True, exist_ok=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class VEXAssertion:
    """Normalised assertion extracted from a VEX document."""

    cve_id: str
    status: str
    justification: Optional[str] = None
    statement: Optional[str] = None
    supplier: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "cve_id": self.cve_id,
            "status": self.status,
            "justification": self.justification,
            "statement": self.statement,
            "supplier": self.supplier,
        }


class VEXIngestor:
    """Parse and persist SPDX/CycloneDX VEX artefacts."""

    CACHE_FILE = _VEX_CACHE / "assertions.json"

    @classmethod
    def ingest_document(
        cls,
        payload: Mapping[str, object] | str | bytes,
        *,
        source: str | None = None,
        supplier: str | None = None,
    ) -> Dict[str, object]:
        """Parse a VEX document and persist the resulting assertions.

        The method is intentionally tolerant: as long as the payload contains
        either SPDX `statements` or CycloneDX `vulnerabilities`, the
        assertions are normalised and cached for subsequent enrichment.
        """

        document = cls._coerce_payload(payload)
        assertions = cls._parse(document, supplier=supplier)

        if not assertions:
            logger.warning("VEX ingestion completed without usable assertions", source=source)

        cls._write_cache(assertions, source=source)
        return {
            "count": len(assertions),
            "source": source,
            "stored_at": _now(),
        }

    @classmethod
    def load_assertions(cls) -> Dict[str, VEXAssertion]:
        """Return the cached assertions keyed by CVE identifier."""

        if not cls.CACHE_FILE.exists():
            return {}

        try:
            cached = json.loads(cls.CACHE_FILE.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.error("Failed to read cached VEX assertions", error=str(exc))
            return {}

        assertions: Dict[str, VEXAssertion] = {}
        for entry in cached.get("assertions", []):
            if not isinstance(entry, Mapping):
                continue
            cve = str(entry.get("cve_id") or "").strip().upper()
            status = str(entry.get("status") or "").strip().lower()
            if not cve or not status:
                continue
            assertions[cve] = VEXAssertion(
                cve_id=cve,
                status=status,
                justification=(
                    str(entry.get("justification")) if entry.get("justification") else None
                ),
                statement=(
                    str(entry.get("statement")) if entry.get("statement") else None
                ),
                supplier=(
                    str(entry.get("supplier")) if entry.get("supplier") else None
                ),
            )
        return assertions

    @classmethod
    def apply_assertions(
        cls,
        findings: Iterable[Mapping[str, object]],
    ) -> List[Dict[str, object]]:
        """Return findings with VEX suppressions applied.

        Findings with `not_affected` assertions inherit the VEX metadata and
        are flagged as suppressed so the downstream decision logic can skip
        remediation actions.
        """

        assertions = cls.load_assertions()
        if not assertions:
            return [dict(f) for f in findings or []]

        enriched: List[Dict[str, object]] = []
        for finding in findings or []:
            if not isinstance(finding, Mapping):
                continue

            clone: Dict[str, object] = dict(finding)
            cve = clone.get("cve_id") or clone.get("cve") or clone.get("id")
            if isinstance(cve, str):
                assertion = assertions.get(cve.strip().upper())
            else:
                assertion = None

            if assertion is None:
                enriched.append(clone)
                continue

            clone.setdefault("vex", {})
            if isinstance(clone["vex"], MutableMapping):
                vex_map = dict(clone["vex"])
            else:
                vex_map = {}

            vex_map.update(assertion.to_dict())
            vex_map.setdefault("suppression_reason", assertion.status)
            vex_map.setdefault("asserted_at", _now())
            clone["vex"] = vex_map

            if assertion.status == "not_affected":
                clone["suppressed"] = True
                clone.setdefault("suppression_reason", "supplier_not_affected")

            enriched.append(clone)

        return enriched

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_payload(payload: Mapping[str, object] | str | bytes) -> Mapping[str, object]:
        if isinstance(payload, Mapping):
            return payload
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        if isinstance(payload, str):
            return json.loads(payload)
        raise TypeError("Unsupported VEX payload type")

    @classmethod
    def _parse(
        cls,
        document: Mapping[str, object],
        *,
        supplier: str | None = None,
    ) -> List[VEXAssertion]:
        assertions: List[VEXAssertion] = []
        assertions.extend(cls._parse_spdx(document, supplier=supplier))
        assertions.extend(cls._parse_cyclonedx(document, supplier=supplier))
        return assertions

    @staticmethod
    def _parse_spdx(
        document: Mapping[str, object],
        *,
        supplier: str | None = None,
    ) -> List[VEXAssertion]:
        statements = document.get("statements")
        if not isinstance(statements, Iterable):
            return []

        assertions: List[VEXAssertion] = []
        for item in statements:
            if not isinstance(item, Mapping):
                continue
            vuln = item.get("vulnerability") or item.get("vulnerability_id")
            status = item.get("status")
            if not isinstance(vuln, str) or not isinstance(status, str):
                continue
            assertions.append(
                VEXAssertion(
                    cve_id=vuln.strip().upper(),
                    status=status.strip().lower(),
                    justification=(
                        str(item.get("justification")) if item.get("justification") else None
                    ),
                    statement=(str(item.get("statement")) if item.get("statement") else None),
                    supplier=supplier or str(document.get("supplier", "")) or None,
                )
            )
        return assertions

    @staticmethod
    def _parse_cyclonedx(
        document: Mapping[str, object],
        *,
        supplier: str | None = None,
    ) -> List[VEXAssertion]:
        vulnerabilities = document.get("vulnerabilities")
        if not isinstance(vulnerabilities, Iterable):
            return []

        assertions: List[VEXAssertion] = []
        for entry in vulnerabilities:
            if not isinstance(entry, Mapping):
                continue
            identifier = entry.get("id") or entry.get("cve") or entry.get("vuln")
            analysis = entry.get("analysis")
            if not isinstance(identifier, str) or not isinstance(analysis, Mapping):
                continue
            state = analysis.get("state") or analysis.get("status")
            if not isinstance(state, str):
                continue
            assertions.append(
                VEXAssertion(
                    cve_id=identifier.strip().upper(),
                    status=state.strip().lower(),
                    justification=(
                        str(analysis.get("justification")) if analysis.get("justification") else None
                    ),
                    statement=(
                        str(analysis.get("response")) if analysis.get("response") else None
                    ),
                    supplier=supplier or str(entry.get("source", "")) or None,
                )
            )
        return assertions

    @classmethod
    def _write_cache(cls, assertions: List[VEXAssertion], *, source: str | None) -> None:
        cls.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "stored_at": _now(),
            "source": source,
            "assertions": [assertion.to_dict() for assertion in assertions],
        }
        cls.CACHE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


__all__ = ["VEXIngestor", "VEXAssertion"]
