"""Unified per-stage processor used by the CLI and ingest API."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import shutil
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from apps.api.normalizers import InputNormalizer, NormalizedSARIF, NormalizedSBOM


def _current_utc_timestamp() -> str:
    """Return an ISO8601 timestamp with optional test overrides."""

    override = os.environ.get("FIXOPS_FAKE_NOW")
    if override:
        candidate = override.strip()
        if not candidate:
            return datetime.utcnow().isoformat() + "Z"
        if candidate.endswith("Z"):
            return candidate
        return f"{candidate}Z"
    return datetime.utcnow().isoformat() + "Z"


def _zip_date_time_tuple() -> tuple[int, int, int, int, int, int]:
    """Return a deterministic ZIP timestamp aligned with :func:`_current_utc_timestamp`."""

    raw_timestamp = _current_utc_timestamp()
    trimmed = raw_timestamp.rstrip("Z")
    try:
        parsed = datetime.fromisoformat(trimmed)
    except ValueError:
        parsed = datetime.utcnow()
    return (
        parsed.year,
        parsed.month,
        parsed.day,
        parsed.hour,
        parsed.minute,
        parsed.second,
    )


@dataclass(slots=True)
class StageSummary:
    stage: str
    app_id: str
    run_id: str
    output_file: Path
    outputs_dir: Path
    signatures: list[Path]
    transparency_index: Path | None
    bundle: Path | None
    verified: Optional[bool]


class StageRunner:
    """Coordinate canonical IO handling for the FixOps stages."""

    _INPUT_FILENAMES: dict[str, str] = {
        "requirements": "requirements-input.csv",
        "design": "design-input.json",
        "build": "sbom.json",
        "test": "scanner.sarif",
        "deploy": "tfplan.json",
        "operate": "ops-telemetry.json",
        "decision": "decision-input.json",
    }

    _OUTPUT_FILENAMES: dict[str, str] = {
        "requirements": "requirements.json",
        "design": "design.manifest.json",
        "build": "build.report.json",
        "test": "test.report.json",
        "deploy": "deploy.manifest.json",
        "operate": "operate.snapshot.json",
        "decision": "decision.json",
    }

    _RISK_RULES: dict[str, str] = {
        "pkg:maven/log4j-core@2.14.0": "historical RCE family",
        "pkg:maven/log4j-core@2.15.0": "historical RCE family",
    }

    _APP_ID_PATTERN = re.compile(r"^APP-\d{4,}$", re.IGNORECASE)

    def __init__(
        self, registry, allocator, signer, *, normalizer: InputNormalizer | None = None
    ) -> None:
        self.registry = registry
        self.allocator = allocator
        self.signer = signer
        self.normalizer = normalizer or InputNormalizer()

    # ------------------------------------------------------------------
    def run_stage(
        self,
        stage: str,
        input_path: Optional[Path],
        *,
        app_name: Optional[str] = None,
        app_id: Optional[str] = None,
        output_path: Optional[Path] = None,
        mode: str = "demo",
        sign: bool = False,
        verify: bool = False,
        verbose: bool = False,
    ) -> StageSummary:
        stage_key = stage.lower().strip()
        if stage_key not in self._OUTPUT_FILENAMES:
            raise ValueError(f"Unsupported stage '{stage}'")

        input_bytes: bytes | None = None
        source_path = None
        if input_path is not None:
            source_path = input_path.expanduser().resolve()
            if not source_path.exists():
                raise FileNotFoundError(source_path)
            input_bytes = source_path.read_bytes()

        sign_requested = sign and self._signing_available()
        design_payload: Dict[str, Any] | None = None

        app_id, app_name = self._resolve_identity(app_id, app_name)

        if stage_key == "design":
            design_payload = self._load_design_payload(input_bytes, source_path)  # type: ignore[assignment]
            if app_name and design_payload is not None:
                design_payload.setdefault("app_name", app_name)
            if design_payload is not None:
                design_payload = self.allocator.ensure_ids(design_payload)
            if app_id and design_payload is not None:
                # Preserve explicit identifiers passed on the command line but allow
                # the design document to override implicit values minted from the
                # application name.
                design_payload["app_id"] = app_id
            app_id = str(
                (design_payload.get("app_id") if design_payload else None)
                or app_id
                or "APP-0001"
            )
            app_name = str(
                (design_payload.get("app_name") if design_payload else None)
                or app_name
                or app_id
            )
            input_bytes = json.dumps(design_payload, indent=2).encode("utf-8")
        else:
            if app_id and not app_id.startswith("APP-"):
                derived = self.allocator.ensure_ids({"app_name": app_id})
                app_id = str(derived.get("app_id") or app_id)
            if not app_id and app_name:
                derived = self.allocator.ensure_ids({"app_name": app_name})
                app_id = str(derived.get("app_id"))
            if not app_id:
                app_id = "APP-0001"

        context = self.registry.ensure_run(
            app_id, stage=stage_key, sign_outputs=sign_requested
        )

        input_filename = self._INPUT_FILENAMES.get(stage_key)
        if input_filename and input_bytes is not None:
            self.registry.save_input(context, input_filename, input_bytes)

        processor = getattr(self, f"_process_{stage_key}")
        document = processor(
            context,
            input_bytes,
            design_payload=design_payload,
            mode=mode,
            source_path=source_path,
        )
        canonical_name = self._OUTPUT_FILENAMES[stage_key]
        output_file = self.registry.write_output(context, canonical_name, document)

        if output_path is not None:
            output_path = output_path.expanduser()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(output_file, output_path)

        signatures: list[Path] = []
        transparency_path: Path | None = None
        verified: Optional[bool] = None

        if sign_requested:
            envelope = self.signer.sign_manifest(document)
            digest = envelope.get("digest", {}).get("sha256")
            kid = envelope.get("kid")
            signature_path = self.registry.write_signed_manifest(
                context, canonical_name, envelope
            )
            signatures.append(signature_path)
            if digest:
                transparency_path = self.registry.append_transparency_index(
                    context, canonical_name, digest, kid
                )
            if verify:
                verified = self.signer.verify_manifest(document, envelope)
        elif verify:
            verified = False

        bundle_path: Path | None = None
        if stage_key == "decision":
            bundle_path = context.outputs_dir / "evidence_bundle.zip"

        if verbose:
            print(f"Stage '{stage_key}' complete for {context.app_id}/{context.run_id}")

        return StageSummary(
            stage=stage_key,
            app_id=context.app_id,
            run_id=context.run_id,
            output_file=output_file,
            outputs_dir=context.outputs_dir,
            signatures=signatures,
            transparency_index=transparency_path,
            bundle=bundle_path if bundle_path and bundle_path.exists() else None,
            verified=verified,
        )

    # ------------------------------------------------------------------
    def _process_requirements(
        self,
        context,
        input_bytes: bytes | None,
        *,
        design_payload: Mapping[str, Any] | None,
        mode: str,
        source_path: Path | None,
    ) -> Mapping[str, Any]:
        records: list[dict[str, Any]] = []
        if input_bytes:
            raw_records = self._parse_requirements(io.BytesIO(input_bytes))
            records = self._assign_requirement_ids(raw_records, context.app_id)  # type: ignore[arg-type]
        anchor = self._derive_ssvc_anchor(records)  # type: ignore[arg-type]
        return {
            "app_id": context.app_id,
            "run_id": context.run_id,
            "requirements": records,
            "ssvc_anchor": anchor,
        }

    def _process_design(
        self,
        context,
        input_bytes: bytes | None,
        *,
        design_payload: Mapping[str, Any] | None,
        mode: str,
        source_path: Path | None,
    ) -> Mapping[str, Any]:
        manifest = dict(design_payload or {})
        components = manifest.get("components") or []
        if isinstance(components, list):
            for component in components:
                if isinstance(component, dict):
                    component.setdefault(
                        "component_id", self._component_token(component.get("name"))
                    )
        manifest.setdefault("app_name", manifest.get("app_id"))
        manifest["design_risk_score"] = self._design_risk_score(components)
        manifest.setdefault("app_id", context.app_id)
        manifest["run_id"] = context.run_id
        return manifest

    def _process_build(
        self,
        context,
        input_bytes: bytes | None,
        *,
        design_payload: Mapping[str, Any] | None,
        mode: str,
        source_path: Path | None,
    ) -> Mapping[str, Any]:
        if not input_bytes:
            raise ValueError("Build stage requires sbom.json input")
        if source_path is not None:
            extras = [
                source_path.parent / "scanner.sarif",
                source_path.parent / "provenance.slsa.json",
            ]
            for extra in extras:
                if extra.exists():
                    self.registry.save_input(context, extra.name, extra.read_bytes())
        sbom: NormalizedSBOM = self.normalizer.load_sbom(input_bytes)
        components = [
            component.to_dict() for component in getattr(sbom, "components", [])
        ]
        risk_flags = []
        for component in components:
            identifier = component.get("purl") or component.get("name")
            if not identifier:
                continue
            reason = self._RISK_RULES.get(str(identifier))
            if (
                not reason
                and isinstance(identifier, str)
                and "log4j" in identifier.lower()
            ):
                reason = "historical RCE family"
            if reason:
                risk_flags.append({"purl": str(identifier), "reason": reason})
        links: Dict[str, str] = {}
        for name in ("sbom.json", "provenance.slsa.json"):
            candidate = context.inputs_dir / name
            if candidate.exists():
                key = name.split(".")[0]
                relative = Path("..") / candidate.relative_to(context.run_path)
                links[key] = str(relative)
        component_count = len(components)
        score = min(
            0.45 + 0.1 * len(risk_flags) + min(component_count / 500, 0.15), 0.99
        )
        design_manifest = self._read_optional_json(
            context.outputs_dir / "design.manifest.json"
        )
        app_id = str((design_manifest or {}).get("app_id") or context.app_id)
        return {
            "app_id": app_id,
            "run_id": context.run_id,
            "components_indexed": component_count,
            "risk_flags": risk_flags,
            "links": links,
            "build_risk_score": round(score, 2),
        }

    def _process_test(
        self,
        context,
        input_bytes: bytes | None,
        *,
        design_payload: Mapping[str, Any] | None,
        mode: str,
        source_path: Path | None,
    ) -> Mapping[str, Any]:
        findings, tests_input_override = self._load_test_inputs(
            context, input_bytes, source_path
        )
        tests_input = tests_input_override or self._read_optional_json(
            context.inputs_dir / "tests-input.json"
        )
        severity_counts = Counter(
            finding.get("severity", "low") for finding in findings
        )
        summary = {
            key: severity_counts.get(key, 0)
            for key in ("critical", "high", "medium", "low")
        }
        drift = {"new_findings": len((tests_input or {}).get("new_findings", []))}
        coverage_data = (tests_input or {}).get("coverage")
        if not isinstance(coverage_data, Mapping):
            coverage = {"lines": 0.0, "branches": 0.0}
        else:
            coverage = {
                "lines": round(float(coverage_data.get("lines", 0.0)), 2),
                "branches": round(float(coverage_data.get("branches", 0.0)), 2),
            }
        score = min(
            0.3
            + 0.12 * summary["critical"]
            + 0.1 * summary["high"]
            + 0.02 * drift["new_findings"],
            0.99,
        )
        return {
            "app_id": context.app_id,
            "run_id": context.run_id,
            "summary": summary,
            "drift": drift,
            "coverage": coverage,
            "test_risk_score": round(score, 2),
        }

    def _process_deploy(
        self,
        context,
        input_bytes: bytes | None,
        *,
        design_payload: Mapping[str, Any] | None,
        mode: str,
        source_path: Path | None,
    ) -> Mapping[str, Any]:
        if not input_bytes:
            raise ValueError("Deploy stage requires tfplan.json or k8s manifest input")
        payload = self._load_deploy_payload(input_bytes)
        posture = self._analyse_posture(payload)
        digests = self._extract_digests(context)
        evidence = self._control_evidence(posture)
        score = 0.52
        if posture["public_buckets"]:
            score += 0.16
        if posture.get("tls_policy"):
            score += 0.03
        if posture.get("open_security_groups"):
            score += 0.14
        if posture.get("unpinned_images"):
            score += 0.08
        if posture.get("privileged_containers"):
            score += 0.1
        if posture.get("encryption_gaps"):
            score += 0.05
        return {
            "app_id": context.app_id,
            "run_id": context.run_id,
            "digests": digests,
            "posture": posture,
            "control_evidence": evidence,
            "deploy_risk_score": round(min(score, 0.99), 2),
        }

    def _process_operate(
        self,
        context,
        input_bytes: bytes | None,
        *,
        design_payload: Mapping[str, Any] | None,
        mode: str,
        source_path: Path | None,
    ) -> Mapping[str, Any]:
        telemetry = {}
        if input_bytes:
            telemetry = json.loads(input_bytes.decode("utf-8"))
        build_report = (
            self._read_optional_json(context.outputs_dir / "build.report.json") or {}
        )
        kev_feed = self._read_optional_json(Path("data/feeds/kev.json")) or {}
        epss_feed = self._read_optional_json(Path("data/feeds/epss.json")) or {}
        kev_hits = []
        epss_records = []
        risk_components = (
            build_report.get("risk_flags", [])
            if isinstance(build_report, Mapping)
            else []
        )
        for flag in risk_components:
            if (
                isinstance(flag, Mapping)
                and "log4j" in str(flag.get("purl", "")).lower()
            ):
                kev_hits.append("CVE-2021-44228")
                epss_records.append({"cve": "CVE-2021-44228", "score": 0.97})
                break
        if not kev_hits and isinstance(kev_feed, Mapping):
            kev_hits = list(kev_feed.get("top", []))
        if not epss_records and isinstance(epss_feed, Mapping):
            epss_records = list(epss_feed.get("top", []))
        pressure = 0.4
        latency = (
            telemetry.get("latency_ms_p95") if isinstance(telemetry, Mapping) else None
        )
        if isinstance(latency, (int, float)):
            pressure = min(0.95, max(pressure, latency / 650))
        design_manifest = self._read_optional_json(
            context.outputs_dir / "design.manifest.json"
        )
        service_name = str((design_manifest or {}).get("app_name") or context.app_id)
        score = 0.45 + (0.08 if kev_hits else 0) + (0.06 if pressure >= 0.6 else 0.02)
        return {
            "app_id": context.app_id,
            "run_id": context.run_id,
            "kev_hits": kev_hits,
            "epss": epss_records,
            "pressure_by_service": [
                {"service": service_name, "pressure": round(pressure, 2)}
            ],
            "operate_risk_score": round(min(score, 0.99), 2),
        }

    def _process_decision(
        self,
        context,
        input_bytes: bytes | None,
        *,
        design_payload: Mapping[str, Any] | None,
        mode: str,
        source_path: Path | None,
    ) -> Mapping[str, Any]:
        requested = None
        if input_bytes:
            requested = json.loads(input_bytes.decode("utf-8"))
        documents = self._collect_documents(context, requested)
        deploy_manifest = documents.get("deploy", {})
        operate_snapshot = documents.get("operate", {})
        requirements = documents.get("requirements", {})
        build_report = documents.get("build", {})
        test_report = documents.get("test", {})

        failing_controls = [
            entry.get("control")
            for entry in deploy_manifest.get("control_evidence", [])
            if isinstance(entry, Mapping) and entry.get("result") == "fail"
        ]
        kev_hits = (
            operate_snapshot.get("kev_hits", [])
            if isinstance(operate_snapshot, Mapping)
            else []
        )
        verdict = "DEFER" if failing_controls or kev_hits else "ALLOW"
        top_factors = self._decision_factors(
            build_report, test_report, deploy_manifest, operate_snapshot
        )
        compliance_rollup = self._compliance_rollup(requirements, deploy_manifest)
        confidence = min(0.6 + 0.08 * len(top_factors), 0.95)
        evidence_id = f"ev_{context.app_id}_{mode.lower()}"

        decision_document = {
            "decision": verdict,
            "confidence_score": round(confidence, 2),
            "top_factors": top_factors,
            "compliance_rollup": compliance_rollup,
            "marketplace_recommendations": self._marketplace_recommendations(
                failing_controls
            ),
            "evidence_id": evidence_id,
        }
        decision_document["app_id"] = context.app_id
        decision_document["run_id"] = context.run_id
        documents["decision"] = decision_document
        bundle = self._write_evidence_bundle(context, documents)
        manifest_payload = self._bundle_manifest(documents)
        manifest_bytes = (json.dumps(manifest_payload, indent=2) + "\n").encode("utf-8")
        self.registry.write_binary_output(context, "manifest.json", manifest_bytes)
        with zipfile.ZipFile(bundle, "a") as archive:
            info = zipfile.ZipInfo("manifest.json")
            info.date_time = _zip_date_time_tuple()
            archive.writestr(info, manifest_bytes)

        return decision_document

    # ------------------------------------------------------------------
    def _signing_available(self) -> bool:
        return bool(
            os.environ.get("FIXOPS_SIGNING_KEY")
            and os.environ.get("FIXOPS_SIGNING_KID")
        )

    def _load_design_payload(
        self, input_bytes: bytes | None, input_path: Optional[Path]
    ) -> Mapping[str, Any]:
        if input_bytes is None:
            return {}
        text = input_bytes.decode("utf-8")
        if input_path and input_path.suffix.lower() == ".csv":
            reader = csv.DictReader(io.StringIO(text))
            rows = [
                row
                for row in reader
                if any((value or "").strip() for value in row.values())
            ]
            return {"rows": rows, "columns": reader.fieldnames or []}
        return json.loads(text)

    def _parse_requirements(self, stream: io.BytesIO) -> list[dict[str, Any]]:
        peek = stream.getvalue()
        text = peek.decode("utf-8")
        if text.strip().startswith("{"):
            payload = json.loads(text)
            items = (
                payload.get("requirements", []) if isinstance(payload, Mapping) else []
            )
            records = [
                self._normalise_requirement(item)
                for item in items
                if isinstance(item, Mapping)
            ]
            return records
        stream.seek(0)
        reader = csv.DictReader(io.TextIOWrapper(stream, encoding="utf-8"))
        records = []
        for row in reader:
            if any((value or "").strip() for value in row.values()):
                records.append(self._normalise_requirement(row))
        return records

    def _assign_requirement_ids(
        self, records: list[Mapping[str, Any]], app_id: str | None
    ) -> list[dict[str, Any]]:
        minted: list[dict[str, Any]] = []
        seen: set[str] = set()
        counter = 1
        for record in records:
            normalised = dict(record)
            candidate = str(normalised.get("requirement_id") or "").strip().upper()
            if not candidate.startswith("REQ-"):
                candidate = f"REQ-{counter:04d}"
            while candidate in seen:
                counter += 1
                candidate = f"REQ-{counter:04d}"
            seen.add(candidate)
            counter += 1
            normalised["requirement_id"] = candidate
            normalised.setdefault("Requirement_ID", candidate)
            if app_id:
                normalised.setdefault("app_id", app_id)
            minted.append(normalised)
        return minted

    def _normalise_requirement(self, row: Mapping[str, Any]) -> dict[str, Any]:
        control_refs = row.get("control_refs")
        if isinstance(control_refs, str):
            refs = [token.strip() for token in control_refs.split(";") if token.strip()]
        elif isinstance(control_refs, Iterable):
            refs = [str(token).strip() for token in control_refs if str(token).strip()]
        else:
            refs = []
        return {
            "requirement_id": str(row.get("requirement_id") or "REQ-0000"),
            "feature": str(row.get("feature") or ""),
            "control_refs": refs,
            "data_class": str(row.get("data_class") or "unknown").lower(),
            "pii": self._as_bool(row.get("pii")),
            "internet_facing": self._as_bool(row.get("internet_facing")),
            "notes": str(row.get("notes") or ""),
        }

    def _derive_ssvc_anchor(self, records: list[Mapping[str, Any]]) -> dict[str, Any]:
        internet = any(record.get("internet_facing") for record in records)
        pii = any(record.get("pii") for record in records)
        if internet and pii:
            return {"stakeholder": "mission", "impact_tier": "critical"}
        if internet:
            return {"stakeholder": "mission", "impact_tier": "high"}
        if pii:
            return {"stakeholder": "safety", "impact_tier": "high"}
        return {"stakeholder": "maintenance", "impact_tier": "moderate"}

    def _component_token(self, value: Any) -> str:
        text = str(value or "component").lower().replace(" ", "-")
        cleaned = "".join(
            ch if ch.isalnum() or ch == "-" else "-" for ch in text
        ).strip("-")
        return f"C-{(cleaned or 'component').split('-')[0]}"

    def _design_risk_score(
        self, components: Iterable[Mapping[str, Any]] | None
    ) -> float:
        score = 0.5
        if not components:
            return round(score, 2)
        for component in components:
            if not isinstance(component, Mapping):
                continue
            if str(component.get("exposure", "")).lower() == "internet":
                score += 0.18
            if component.get("pii"):
                score += 0.1
        return round(min(score, 0.99), 2)

    def _load_test_inputs(
        self, context, input_bytes: bytes | None, source_path: Path | None
    ) -> tuple[list[dict[str, Any]], Mapping[str, Any] | None]:
        tests_payload: Mapping[str, Any] | None = None
        sarif_payload: NormalizedSARIF | None = None
        if input_bytes:
            try:
                parsed = json.loads(input_bytes.decode("utf-8"))
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, Mapping) and "runs" not in parsed:
                tests_payload = parsed
            else:
                sarif_payload = self.normalizer.load_sarif(input_bytes)
        else:
            candidate = context.inputs_dir / "scanner.sarif"
            if candidate.exists():
                sarif_payload = self.normalizer.load_sarif(candidate.read_bytes())
        if sarif_payload is None and source_path is not None:
            candidate = source_path.parent / "scanner.sarif"
            if candidate.exists():
                sarif_payload = self.normalizer.load_sarif(candidate.read_bytes())
        findings: list[dict[str, Any]] = []
        if isinstance(sarif_payload, NormalizedSARIF):
            for finding in sarif_payload.findings:
                level = (finding.level or "low").lower()
                severity = {
                    "error": "critical",
                    "warning": "high",
                    "note": "medium",
                }.get(level, "low")
                findings.append({"severity": severity})
        if not tests_payload and source_path is not None:
            candidate = source_path.parent / "tests-input.json"
            if candidate.exists():
                try:
                    tests_payload = json.loads(candidate.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    tests_payload = None
        if tests_payload:
            self.registry.save_input(context, "tests-input.json", tests_payload)
        return findings, tests_payload

    def _load_deploy_payload(self, input_bytes: bytes) -> Mapping[str, Any]:
        text = input_bytes.decode("utf-8")
        trimmed = text.lstrip()
        if trimmed.startswith("{"):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError("Deploy manifest is not valid JSON") from exc
        else:
            try:
                import yaml  # type: ignore

                payload = yaml.safe_load(text)
            except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
                raise ValueError(
                    "YAML deploy manifests require PyYAML; install it or submit JSON"
                ) from exc
            except Exception as exc:
                raise ValueError("Deploy manifest is not valid YAML") from exc
        if payload is None:
            payload = {}
        if isinstance(payload, list):
            payload = {"resources": payload}
        if not isinstance(payload, Mapping):
            raise ValueError("Deploy manifest must decode to a mapping or list")
        return payload

    def _analyse_posture(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        public_buckets: set[str] = set()
        open_security_groups: set[str] = set()
        unpinned_images: set[str] = set()
        privileged_containers: set[str] = set()
        encryption_gaps: set[str] = set()
        tls_policy = None

        resources: Iterable[Any]
        resources_field = (
            payload.get("resources") if isinstance(payload, Mapping) else None
        )
        items_field = payload.get("items") if isinstance(payload, Mapping) else None
        if isinstance(resources_field, Iterable) and not isinstance(
            resources_field, (str, bytes, bytearray)
        ):
            resources = resources_field or []
        elif isinstance(items_field, Iterable) and not isinstance(
            items_field, (str, bytes, bytearray)
        ):
            resources = items_field or []
        else:
            resources = [payload]

        def _normalise_cidr_values(raw: Any) -> list[str]:
            if isinstance(raw, (str, bytes, bytearray)):
                return [str(raw)]
            if isinstance(raw, Iterable) and not isinstance(
                raw, (str, bytes, bytearray)
            ):
                values: list[str] = []
                for item in raw:
                    if item is None:
                        continue
                    values.append(str(item))
                return values
            return []

        def _has_open_cidr(values: Iterable[str]) -> bool:
            return any(value in {"0.0.0.0/0", "::/0"} for value in values)

        for resource in resources:
            if not isinstance(resource, Mapping):
                continue
            rtype = resource.get("type") or resource.get("kind")
            name = str(
                resource.get("name")
                or resource.get("metadata", {}).get("name")
                or "resource"
            )
            changes_raw = resource.get("changes")
            changes = changes_raw if isinstance(changes_raw, Mapping) else {}
            after_raw = changes.get("after") if isinstance(changes, Mapping) else None
            after = after_raw if isinstance(after_raw, Mapping) else {}

            if rtype == "aws_s3_bucket":
                acl = (
                    after.get("acl") if isinstance(after, Mapping) else None
                ) or resource.get("acl")
                if acl == "public-read":
                    public_buckets.add(name)
                encryption = (
                    after.get("server_side_encryption_configuration")
                    if isinstance(after, Mapping)
                    else None
                )
                if not encryption:
                    encryption_gaps.add(name)

            if rtype in {"aws_lb_listener", "Ingress", "Service"}:
                candidate_tls = (
                    after.get("ssl_policy") if isinstance(after, Mapping) else None
                )
                if not candidate_tls:
                    spec = resource.get("spec")
                    if isinstance(spec, Mapping):
                        tls_section = spec.get("tls")
                        if isinstance(tls_section, list) and tls_section:
                            first = tls_section[0]
                            if isinstance(first, Mapping):
                                candidate_tls = first.get("secretName")
                if candidate_tls:
                    tls_policy = candidate_tls

            if rtype == "aws_security_group":
                ingress_rules = (
                    (after.get("ingress") if isinstance(after, Mapping) else None)
                    or resource.get("ingress")
                    or []
                )
                if isinstance(ingress_rules, Mapping):
                    ingress_rules = [ingress_rules]
                for rule in ingress_rules:
                    if not isinstance(rule, Mapping):
                        continue
                    cidr_values = _normalise_cidr_values(
                        rule.get("cidr_blocks") or rule.get("cidrs") or rule.get("cidr")
                    )
                    ipv6_values = _normalise_cidr_values(rule.get("ipv6_cidr_blocks"))
                    if _has_open_cidr(cidr_values + ipv6_values):
                        open_security_groups.add(name)

            if rtype == "aws_security_group_rule":
                cidr_fields = []
                for key in ("cidr_blocks", "ipv6_cidr_blocks"):
                    if isinstance(after, Mapping) and key in after:
                        cidr_fields.extend(_normalise_cidr_values(after.get(key)))
                    elif key in resource:
                        cidr_fields.extend(_normalise_cidr_values(resource.get(key)))
                if _has_open_cidr(cidr_fields):
                    open_security_groups.add(name)

            if rtype in {"aws_db_instance", "aws_rds_cluster"}:
                encrypted = (
                    after.get("storage_encrypted")
                    if isinstance(after, Mapping)
                    else None
                )
                if encrypted is False or encrypted is None:
                    encryption_gaps.add(name)

            if rtype in {"Deployment", "StatefulSet", "DaemonSet", "Pod"}:
                spec = resource.get("spec")
                if isinstance(spec, Mapping) and "template" in spec:
                    template = spec.get("template")
                    spec = (
                        template.get("spec") if isinstance(template, Mapping) else spec
                    )
                if isinstance(spec, Mapping):
                    containers = spec.get("containers") or []
                    if isinstance(containers, Mapping):
                        containers = [containers]
                    for container in containers:
                        if not isinstance(container, Mapping):
                            continue
                        cname = str(container.get("name") or name)
                        image = container.get("image")
                        if isinstance(image, str):
                            if ":" not in image or image.endswith(":latest"):
                                unpinned_images.add(f"{cname}@{image}")
                        security_context = container.get("securityContext")
                        if isinstance(
                            security_context, Mapping
                        ) and security_context.get("privileged"):
                            privileged_containers.add(cname)

        return {
            "public_buckets": sorted(public_buckets),
            "tls_policy": tls_policy,
            "open_security_groups": sorted(open_security_groups),
            "unpinned_images": sorted(unpinned_images),
            "privileged_containers": sorted(privileged_containers),
            "encryption_gaps": sorted(encryption_gaps),
        }

    def _extract_digests(self, context) -> list[str]:
        provenance = context.inputs_dir / "provenance.slsa.json"
        if not provenance.exists():
            return []
        payload = json.loads(provenance.read_text(encoding="utf-8"))
        digests: list[str] = []
        for subject in payload.get("subject", []) or []:
            if isinstance(subject, Mapping):
                digest = subject.get("digest")
                if isinstance(digest, Mapping) and digest.get("sha256"):
                    digests.append(f"sha256:{digest['sha256']}")
        return digests

    def _control_evidence(self, posture: Mapping[str, Any]) -> list[dict[str, Any]]:
        public_buckets = posture.get("public_buckets", [])
        tls_policy = posture.get("tls_policy")
        open_security_groups = posture.get("open_security_groups", [])
        unpinned_images = posture.get("unpinned_images", [])
        privileged_containers = posture.get("privileged_containers", [])
        encryption_gaps = posture.get("encryption_gaps", [])

        evidence = []
        evidence.append(
            {
                "control": "ISO27001:AC-2",
                "result": "fail" if public_buckets else "pass",
                "source": "public_buckets" if public_buckets else "checks",
            }
        )
        evidence.append(
            {
                "control": "ISO27001:AC-1",
                "result": "pass" if tls_policy else "fail",
                "source": "tls_policy",
            }
        )
        evidence.append(
            {
                "control": "ISO27001:AC-3",
                "result": "fail" if open_security_groups else "pass",
                "source": "open_security_groups" if open_security_groups else "checks",
            }
        )
        evidence.append(
            {
                "control": "CIS-K8S:5.4.1",
                "result": "fail" if unpinned_images else "pass",
                "source": "unpinned_images" if unpinned_images else "checks",
            }
        )
        evidence.append(
            {
                "control": "CIS-K8S:5.2.2",
                "result": "fail" if privileged_containers else "pass",
                "source": (
                    "privileged_containers" if privileged_containers else "checks"
                ),
            }
        )
        evidence.append(
            {
                "control": "ISO27001:SC-28",
                "result": "fail" if encryption_gaps else "pass",
                "source": "encryption_gaps" if encryption_gaps else "checks",
            }
        )
        return evidence

    def _collect_documents(
        self, context, requested: Mapping[str, Any] | None
    ) -> dict[str, Mapping[str, Any]]:
        artefacts = {
            "requirements": "requirements.json",
            "design": "design.manifest.json",
            "build": "build.report.json",
            "test": "test.report.json",
            "deploy": "deploy.manifest.json",
            "operate": "operate.snapshot.json",
        }
        documents: dict[str, Mapping[str, Any]] = {}
        for key, filename in artefacts.items():
            path = context.outputs_dir / filename
            if path.exists():
                documents[key] = json.loads(path.read_text(encoding="utf-8"))
        if requested and isinstance(requested, Mapping):
            for filename in requested.get("artefacts", []) or []:
                if not isinstance(filename, str):
                    continue
                path = context.outputs_dir / filename
                if path.exists():
                    key = filename.split(".")[0]
                    documents[key] = json.loads(path.read_text(encoding="utf-8"))
        return documents

    def _decision_factors(
        self,
        build: Mapping[str, Any],
        test: Mapping[str, Any],
        deploy: Mapping[str, Any],
        operate: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        factors: list[dict[str, Any]] = []
        summary = test.get("summary") if isinstance(test, Mapping) else {}
        highest = None
        if isinstance(summary, Mapping):
            for level in ("critical", "high", "medium", "low"):
                if summary.get(level):
                    highest = level
                    break
        if highest:
            factors.append(
                {
                    "name": f"{highest.title()} severity detected",
                    "weight": 0.4 if highest == "critical" else 0.32,
                    "rationale": (
                        f"Testing summary reported {summary.get(highest) if isinstance(summary, Mapping) else 0} {highest} findings"
                    ),
                }
            )
        public_buckets = (
            deploy.get("posture", {}).get("public_buckets", [])
            if isinstance(deploy, Mapping)
            else []
        )
        if public_buckets:
            factors.append(
                {
                    "name": "Guardrail violation",
                    "weight": 0.4,
                    "rationale": "Deployment posture shows publicly exposed storage buckets",
                }
            )
        kev_hits = operate.get("kev_hits", []) if isinstance(operate, Mapping) else []
        if kev_hits:
            factors.append(
                {
                    "name": "Elevated exploit pressure",
                    "weight": 0.35,
                    "rationale": "Known exploited vulnerability feed triggered for monitored components",
                }
            )
        if not factors:
            factors.append(
                {
                    "name": "Stable release",
                    "weight": 0.2,
                    "rationale": "No critical findings, posture gaps, or exploit signals detected",
                }
            )
        return factors[:3]

    def _compliance_rollup(
        self,
        requirements: Mapping[str, Any],
        deploy: Mapping[str, Any],
    ) -> dict[str, Any]:
        controls: dict[str, float] = {}
        evidence_lookup = {}
        for entry in deploy.get("control_evidence", []) or []:
            if isinstance(entry, Mapping):
                evidence_lookup[str(entry.get("control"))] = entry
        for requirement in requirements.get("requirements", []) or []:
            if not isinstance(requirement, Mapping):
                continue
            for control_ref in requirement.get("control_refs", []) or []:
                control_id = str(control_ref)
                evidence = evidence_lookup.get(control_id, {})
                result = evidence.get("result")
                coverage = 1.0 if result == "pass" else 0.0 if result == "fail" else 0.5
                controls[control_id] = coverage
        control_rollup = [
            {"id": control_id, "coverage": round(value, 2)}
            for control_id, value in sorted(controls.items())
        ]
        frameworks: dict[str, list[float]] = {}
        for control_id, value in controls.items():
            framework = control_id.split(":")[0] if ":" in control_id else "generic"
            frameworks.setdefault(framework, []).append(value)
        framework_rollup = [
            {"name": name, "coverage": round(sum(values) / len(values), 2)}
            for name, values in frameworks.items()
        ]
        return {"controls": control_rollup, "frameworks": framework_rollup}

    def _marketplace_recommendations(
        self, failing_controls: list[Any]
    ) -> list[dict[str, Any]]:
        if not failing_controls:
            return []
        matches = sorted({str(control) for control in failing_controls if control})
        return [
            {
                "id": "guardrail-remediation",
                "title": "Enable auto-remediation playbooks",
                "match": matches,
            }
        ]

    def _write_evidence_bundle(
        self, context, documents: Mapping[str, Mapping[str, Any]]
    ) -> Path:
        bundle_path = context.outputs_dir / "evidence_bundle.zip"
        with zipfile.ZipFile(bundle_path, "w") as archive:
            for key, filename in self._OUTPUT_FILENAMES.items():
                document = documents.get(key)
                if isinstance(document, Mapping):
                    info = zipfile.ZipInfo(filename)
                    info.date_time = _zip_date_time_tuple()
                    archive.writestr(
                        info, json.dumps(document, indent=2, sort_keys=True) + "\n"
                    )
        return bundle_path

    def _bundle_manifest(
        self, documents: Mapping[str, Mapping[str, Any]]
    ) -> Mapping[str, Any]:
        entries = {}
        for key, filename in self._OUTPUT_FILENAMES.items():
            document = documents.get(key)
            if not isinstance(document, Mapping):
                continue
            digest = hashlib.sha256(
                json.dumps(document, sort_keys=True).encode("utf-8")
            ).hexdigest()
            entries[filename] = digest
        return {
            "bundle": "evidence_bundle.zip",
            "documents": entries,
            "generated_at": _current_utc_timestamp(),
        }

    def _read_optional_json(self, path: Path) -> Mapping[str, Any] | None:
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _as_bool(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"true", "yes", "1"}
        return bool(value)

    def _resolve_identity(
        self, app_id: Optional[str], app_name: Optional[str]
    ) -> tuple[Optional[str], Optional[str]]:
        normalised_id = app_id.strip().upper() if isinstance(app_id, str) else None
        if normalised_id and not self._APP_ID_PATTERN.match(normalised_id):
            normalised_id = None

        normalised_name = app_name.strip() if isinstance(app_name, str) else None
        if normalised_name and self._APP_ID_PATTERN.match(normalised_name.upper()):
            normalised_id = normalised_name.upper()
            normalised_name = None

        return normalised_id, normalised_name


__all__ = ["StageRunner", "StageSummary"]
