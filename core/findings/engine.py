from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # Support "Z" suffix.
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    return None


def _normalise_path(value: Optional[str]) -> str:
    if not value:
        return ""
    text = str(value).strip().replace("\\", "/")
    # Strip URI schemes.
    text = re.sub(r"^[a-zA-Z]+://", "", text)
    # Strip common absolute prefixes (/workspace, /app, drive letters).
    text = re.sub(r"^/workspace/", "", text)
    text = re.sub(r"^/app/", "", text)
    text = re.sub(r"^[A-Za-z]:/", "", text)
    # Drop trailing line numbers ("file.py:123").
    text = re.sub(r":\d+$", "", text)
    # Collapse duplicate slashes.
    text = re.sub(r"/{2,}", "/", text)
    return text


def _normalise_text(value: Optional[str], *, max_len: int = 200) -> str:
    if not value:
        return ""
    text = str(value).strip().lower()
    text = re.sub(r"\s+", " ", text)
    # Remove volatile tokens (UUIDs, long hex strings).
    text = re.sub(r"\b[0-9a-f]{12,}\b", "", text)
    text = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "", text)  # noqa: E501
    text = text.strip()
    if len(text) > max_len:
        text = text[:max_len]
    return text


def _hash16(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class CanonicalFinding:
    """A minimal canonical representation used for deduplication and correlation."""

    finding_id: str
    stage: str
    source: str
    title: str
    description: str
    severity: str
    rule_id: Optional[str] = None
    cve_id: Optional[str] = None
    application_id: Optional[str] = None
    service_id: Optional[str] = None
    component: Optional[str] = None
    package: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = None
    asset_id: Optional[str] = None
    observed_at: str = ""
    raw: Dict[str, Any] = None  # type: ignore[assignment]
    fingerprint: str = ""
    correlation_key: str = ""
    deduplicated_from: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.finding_id,
            "stage": self.stage,
            "source": self.source,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "observed_at": self.observed_at,
            "fingerprint": self.fingerprint,
            "correlation_key": self.correlation_key,
        }
        for key, value in (
            ("rule_id", self.rule_id),
            ("cve_id", self.cve_id),
            ("application_id", self.application_id),
            ("service_id", self.service_id),
            ("component", self.component),
            ("package", self.package),
            ("file_path", self.file_path),
            ("line", self.line),
            ("asset_id", self.asset_id),
        ):
            if value is not None and value != "":
                payload[key] = value
        if self.deduplicated_from:
            payload["deduplicated_from"] = list(self.deduplicated_from)
        if self.raw:
            payload["raw"] = self.raw
        return payload


class DedupCorrelationEngine:
    """Deduplicate and correlate heterogeneous findings into case objects."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None) -> None:
        self.config = dict(config or {})
        self.dedup_window_seconds = int(self.config.get("dedup_window_seconds") or 0)
        if self.dedup_window_seconds <= 0:
            # Default: 24 hours.
            self.dedup_window_seconds = 24 * 60 * 60

    def fingerprint(self, finding: Mapping[str, Any]) -> str:
        tool = _normalise_text(str(finding.get("source") or ""), max_len=64)
        stage = _normalise_text(str(finding.get("stage") or ""), max_len=32)
        cve_id = _normalise_text(str(finding.get("cve_id") or ""), max_len=64)
        rule_id = _normalise_text(str(finding.get("rule_id") or ""), max_len=128)
        component = _normalise_text(str(finding.get("component") or ""), max_len=128)
        package = _normalise_text(str(finding.get("package") or ""), max_len=256)
        file_path = _normalise_path(str(finding.get("file_path") or ""))
        title = _normalise_text(str(finding.get("title") or ""), max_len=200)
        # Do NOT include timestamps, scan ids, or absolute paths.
        key = "|".join(
            part
            for part in (
                tool,
                stage,
                cve_id,
                rule_id,
                component,
                package,
                file_path,
                title,
            )
            if part
        )
        return _hash16(key)

    def correlation_key(self, finding: Mapping[str, Any]) -> str:
        # Correlate across stages by shared identifiers and stable location.
        cve_id = _normalise_text(str(finding.get("cve_id") or ""), max_len=64)
        rule_id = _normalise_text(str(finding.get("rule_id") or ""), max_len=128)
        application_id = _normalise_text(str(finding.get("application_id") or ""), max_len=128)
        service_id = _normalise_text(str(finding.get("service_id") or ""), max_len=128)
        component = _normalise_text(str(finding.get("component") or ""), max_len=128)
        asset_id = _normalise_text(str(finding.get("asset_id") or ""), max_len=200)
        package = _normalise_text(str(finding.get("package") or ""), max_len=256)
        location = _normalise_path(str(finding.get("file_path") or "")) or _normalise_text(
            str(finding.get("location") or ""), max_len=200
        )
        # If nothing strong exists, fall back to a title-based cluster.
        title = _normalise_text(str(finding.get("title") or ""), max_len=200)
        key = "|".join(
            part
            for part in (
                cve_id,
                rule_id,
                package,
                component,
                asset_id,
                service_id,
                application_id,
                location,
                title,
            )
            if part
        )
        return _hash16(key)

    def canonicalize_pipeline_result(self, result: Mapping[str, Any]) -> List[CanonicalFinding]:
        findings: List[CanonicalFinding] = []
        observed_at = str(result.get("timestamp") or _now_iso())

        crosswalk = result.get("crosswalk") or []
        if isinstance(crosswalk, Sequence):
            for row_idx, entry in enumerate(crosswalk):
                if not isinstance(entry, Mapping):
                    continue
                design_row = entry.get("design_row") if isinstance(entry.get("design_row"), Mapping) else {}
                component_name = str(design_row.get("component") or "").strip() or None
                service_name = str(design_row.get("service") or "").strip() or None

                sarif_findings = entry.get("findings") or []
                if isinstance(sarif_findings, Sequence):
                    for idx, raw in enumerate(sarif_findings):
                        if not isinstance(raw, Mapping):
                            continue
                        rule_id = raw.get("rule_id")
                        message = raw.get("message") or ""
                        level = str(raw.get("level") or "warning").lower()
                        file_path = raw.get("file") or raw.get("file_path")
                        line = raw.get("line")
                        tool = raw.get("tool_name") or "sarif"
                        finding_id = f"sarif:{row_idx}:{idx}:{rule_id or 'rule'}"
                        base = {
                            "id": finding_id,
                            "stage": "build",
                            "source": str(tool),
                            "title": str(rule_id or "SARIF") + (f" - {message[:80]}" if message else ""),
                            "description": str(message or ""),
                            "severity": level,
                            "rule_id": str(rule_id) if rule_id else None,
                            "application_id": None,
                            "service_id": service_name,
                            "component": component_name,
                            "file_path": str(file_path) if file_path else None,
                            "line": int(line) if isinstance(line, int) else None,
                            "observed_at": observed_at,
                        }
                        fp = self.fingerprint(base)
                        ck = self.correlation_key(base)
                        findings.append(
                            CanonicalFinding(
                                finding_id=finding_id,
                                stage="build",
                                source=str(tool),
                                title=base["title"],
                                description=base["description"],
                                severity=level,
                                rule_id=base.get("rule_id"),
                                application_id=None,
                                service_id=service_name,
                                component=component_name,
                                file_path=base.get("file_path"),
                                line=base.get("line"),
                                observed_at=observed_at,
                                raw=dict(raw),
                                fingerprint=fp,
                                correlation_key=ck,
                            )
                        )

                cves = entry.get("cves") or []
                if isinstance(cves, Sequence):
                    for idx, raw in enumerate(cves):
                        if not isinstance(raw, Mapping):
                            continue
                        cve_id = raw.get("cve_id") or raw.get("id")
                        severity = str(raw.get("severity") or "medium").lower()
                        title = raw.get("title") or (raw.get("raw", {}) or {}).get("shortDescription")
                        finding_id = f"cve:{row_idx}:{idx}:{cve_id or 'cve'}"
                        base = {
                            "id": finding_id,
                            "stage": "build",
                            "source": "cve",
                            "title": str(cve_id or "CVE") + (f" - {str(title)[:80]}" if title else ""),
                            "description": str(title or ""),
                            "severity": severity,
                            "cve_id": str(cve_id) if cve_id else None,
                            "application_id": None,
                            "service_id": service_name,
                            "component": component_name,
                            "observed_at": observed_at,
                        }
                        fp = self.fingerprint(base)
                        ck = self.correlation_key(base)
                        findings.append(
                            CanonicalFinding(
                                finding_id=finding_id,
                                stage="build",
                                source="cve",
                                title=base["title"],
                                description=base["description"],
                                severity=severity,
                                cve_id=base.get("cve_id"),
                                application_id=None,
                                service_id=service_name,
                                component=component_name,
                                observed_at=observed_at,
                                raw=dict(raw),
                                fingerprint=fp,
                                correlation_key=ck,
                            )
                        )

        cnapp_summary = result.get("cnapp_summary")
        if isinstance(cnapp_summary, Mapping):
            cnapp_findings = cnapp_summary.get("findings") or []
            if isinstance(cnapp_findings, Sequence):
                for idx, raw in enumerate(cnapp_findings):
                    if not isinstance(raw, Mapping):
                        continue
                    asset_id = raw.get("asset")
                    finding_type = raw.get("type") or "cnapp"
                    severity = str(raw.get("severity") or "low").lower()
                    finding_id = f"cnapp:{idx}:{asset_id or 'asset'}:{finding_type}"
                    base = {
                        "id": finding_id,
                        "stage": "runtime",
                        "source": "cnapp",
                        "title": str(finding_type),
                        "description": str(raw.get("raw") or raw),
                        "severity": severity,
                        "asset_id": str(asset_id) if asset_id else None,
                        "observed_at": observed_at,
                    }
                    fp = self.fingerprint(base)
                    ck = self.correlation_key(base)
                    findings.append(
                        CanonicalFinding(
                            finding_id=finding_id,
                            stage="runtime",
                            source="cnapp",
                            title=base["title"],
                            description=base["description"],
                            severity=severity,
                            asset_id=base.get("asset_id"),
                            observed_at=observed_at,
                            raw=dict(raw),
                            fingerprint=fp,
                            correlation_key=ck,
                        )
                    )

        return findings

    def canonicalize_artifacts(
        self,
        *,
        sarif: Any,
        cve: Any,
        cnapp: Any | None = None,
        observed_at: Optional[str] = None,
    ) -> List[CanonicalFinding]:
        """Canonicalize raw artefacts directly (works even when crosswalk is empty)."""
        findings: List[CanonicalFinding] = []
        seen_at = observed_at or _now_iso()

        sarif_findings = getattr(sarif, "findings", []) if sarif is not None else []
        for idx, entry in enumerate(sarif_findings):
            raw = entry.to_dict() if hasattr(entry, "to_dict") else dict(entry)
            rule_id = raw.get("rule_id")
            message = raw.get("message") or ""
            level = str(raw.get("level") or "warning").lower()
            file_path = raw.get("file") or raw.get("file_path")
            line = raw.get("line")
            tool = raw.get("tool_name") or "sarif"
            finding_id = f"sarif:{idx}:{rule_id or 'rule'}"
            base = {
                "id": finding_id,
                "stage": "build",
                "source": str(tool),
                "title": str(rule_id or "SARIF") + (f" - {message[:80]}" if message else ""),
                "description": str(message or ""),
                "severity": level,
                "rule_id": str(rule_id) if rule_id else None,
                "file_path": str(file_path) if file_path else None,
                "line": int(line) if isinstance(line, int) else None,
                "observed_at": seen_at,
            }
            fp = self.fingerprint(base)
            ck = self.correlation_key(base)
            findings.append(
                CanonicalFinding(
                    finding_id=finding_id,
                    stage="build",
                    source=str(tool),
                    title=base["title"],
                    description=base["description"],
                    severity=level,
                    rule_id=base.get("rule_id"),
                    file_path=base.get("file_path"),
                    line=base.get("line"),
                    observed_at=seen_at,
                    raw=dict(raw),
                    fingerprint=fp,
                    correlation_key=ck,
                )
            )

        cve_records = getattr(cve, "records", []) if cve is not None else []
        for idx, entry in enumerate(cve_records):
            raw = entry.to_dict() if hasattr(entry, "to_dict") else dict(entry)
            cve_id = raw.get("cve_id") or raw.get("cveID") or raw.get("id")
            severity = str(raw.get("severity") or "medium").lower()
            title = raw.get("title") or (raw.get("raw", {}) or {}).get("shortDescription")
            finding_id = f"cve:{idx}:{cve_id or 'cve'}"
            base = {
                "id": finding_id,
                "stage": "build",
                "source": "cve",
                "title": str(cve_id or "CVE") + (f" - {str(title)[:80]}" if title else ""),
                "description": str(title or ""),
                "severity": severity,
                "cve_id": str(cve_id) if cve_id else None,
                "observed_at": seen_at,
            }
            fp = self.fingerprint(base)
            ck = self.correlation_key(base)
            findings.append(
                CanonicalFinding(
                    finding_id=finding_id,
                    stage="build",
                    source="cve",
                    title=base["title"],
                    description=base["description"],
                    severity=severity,
                    cve_id=base.get("cve_id"),
                    observed_at=seen_at,
                    raw=dict(raw),
                    fingerprint=fp,
                    correlation_key=ck,
                )
            )

        if cnapp is not None:
            cnapp_findings = getattr(cnapp, "findings", [])
            for idx, entry in enumerate(cnapp_findings):
                raw = entry.to_dict() if hasattr(entry, "to_dict") else dict(entry)
                asset_id = raw.get("asset")
                finding_type = raw.get("type") or raw.get("finding_type") or "cnapp"
                severity = str(raw.get("severity") or "low").lower()
                finding_id = f"cnapp:{idx}:{asset_id or 'asset'}:{finding_type}"
                base = {
                    "id": finding_id,
                    "stage": "runtime",
                    "source": "cnapp",
                    "title": str(finding_type),
                    "description": str(raw.get("raw") or raw),
                    "severity": severity,
                    "asset_id": str(asset_id) if asset_id else None,
                    "observed_at": seen_at,
                }
                fp = self.fingerprint(base)
                ck = self.correlation_key(base)
                findings.append(
                    CanonicalFinding(
                        finding_id=finding_id,
                        stage="runtime",
                        source="cnapp",
                        title=base["title"],
                        description=base["description"],
                        severity=severity,
                        asset_id=base.get("asset_id"),
                        observed_at=seen_at,
                        raw=dict(raw),
                        fingerprint=fp,
                        correlation_key=ck,
                    )
                )

        return findings

    def deduplicate(self, findings: Iterable[CanonicalFinding]) -> Tuple[List[CanonicalFinding], Dict[str, Any]]:
        # Dedup within a configurable time window per fingerprint.
        window = int(self.dedup_window_seconds)
        buckets: Dict[str, List[CanonicalFinding]] = {}
        for finding in findings:
            buckets.setdefault(finding.fingerprint, []).append(finding)

        kept: List[CanonicalFinding] = []
        deduped_total = 0

        for fp, group in buckets.items():
            if len(group) == 1:
                kept.append(group[0])
                continue

            def _key(item: CanonicalFinding) -> float:
                dt = _parse_iso(item.observed_at) or _parse_iso(_now_iso())
                assert dt is not None
                return dt.timestamp()

            group_sorted = sorted(group, key=_key)
            head = group_sorted[0]
            head_dt = _parse_iso(head.observed_at) or datetime.now(timezone.utc)
            duplicates: List[str] = []
            for candidate in group_sorted[1:]:
                dt = _parse_iso(candidate.observed_at) or head_dt
                if abs((dt - head_dt).total_seconds()) <= window:
                    duplicates.append(candidate.finding_id)
                else:
                    kept.append(candidate)

            if duplicates:
                deduped_total += len(duplicates)
                kept.append(
                    CanonicalFinding(
                        **{
                            **head.__dict__,
                            "deduplicated_from": tuple(duplicates),
                        }
                    )
                )
            else:
                kept.append(head)

        summary = {
            "dedup_window_seconds": window,
            "input_count": sum(len(v) for v in buckets.values()),
            "output_count": len(kept),
            "deduplicated_count": deduped_total,
        }
        return kept, summary

    def correlate(self, findings: Iterable[CanonicalFinding]) -> List[Dict[str, Any]]:
        groups: Dict[str, List[CanonicalFinding]] = {}
        for finding in findings:
            groups.setdefault(finding.correlation_key, []).append(finding)

        cases: List[Dict[str, Any]] = []
        for key, group in groups.items():
            sources = sorted({f.source for f in group if f.source})
            stages = sorted({f.stage for f in group if f.stage})
            severities = [f.severity for f in group if f.severity]
            case = {
                "case_id": key,
                "correlation_key": key,
                "finding_count": len(group),
                "sources": sources,
                "stages": stages,
                "highest_severity": self._highest_severity(severities),
                "findings": [f.to_dict() for f in group],
            }
            cases.append(case)

        cases.sort(key=lambda c: (c.get("highest_severity") or "", -int(c.get("finding_count") or 0)))
        return cases

    @staticmethod
    def _highest_severity(severities: Sequence[str]) -> str:
        order = {"low": 1, "info": 1, "medium": 2, "high": 3, "critical": 4}
        best = "low"
        best_rank = 0
        for sev in severities:
            rank = order.get(str(sev).lower(), 0)
            if rank > best_rank:
                best_rank = rank
                best = str(sev).lower()
        return best

