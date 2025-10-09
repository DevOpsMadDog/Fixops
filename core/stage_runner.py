"""Stage-specific processors for the unified FixOps CLI and ingest API."""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Sequence
from zipfile import ZipFile

import yaml

from apps.api.normalizers import InputNormalizer
from src.services import run_registry
from src.services.id_allocator import ensure_ids
from src.services import signing


_INPUT_FILENAMES: dict[str, str] = {
    "requirements": "requirements-input.csv",
    "design": "design-input.json",
    "build": "sbom.json",
    "test": "scanner.sarif",
    "deploy": "tfplan.json",
    "operate": "ops-telemetry.json",
    "decision": "decision-input.json",
}


@dataclass(slots=True)
class StageResult:
    stage: str
    app_id: str
    run_id: str
    output_file: Path
    outputs_dir: Path
    signed: list[Path]
    transparency_index: Path | None = None
    bundle: Path | None = None


class StageRunner:
    """Run the per-stage processors used by the CLI and ingest API."""

    def __init__(self, *, normalizer: InputNormalizer | None = None) -> None:
        self._normalizer = normalizer or InputNormalizer()

    # Public API -----------------------------------------------------------------
    def run_stage(
        self,
        stage: str,
        input_path: Path | None,
        *,
        app_name: str | None = None,
        app_id: str | None = None,
        output_path: Path | None = None,
        mode: str | None = None,
        sign: bool = False,
        verify: bool = False,
        verbose: bool = False,
    ) -> StageResult:
        stage_key = stage.lower()
        if stage_key not in _INPUT_FILENAMES:
            raise ValueError(f"Unsupported stage '{stage}'")

        payload_hint: Mapping[str, Any] | None = None
        if stage_key == "design" and input_path is not None:
            payload_hint = self._load_design_payload(input_path)
            payload_hint = ensure_ids(payload_hint)
            if not app_id:
                app_id = str(payload_hint.get("app_id") or app_name or "APP-UNKNOWN")
        elif stage_key == "requirements" and input_path is not None:
            payload_hint = self._load_requirements_payload(input_path)

        sign_outputs = sign and self._signing_available()
        context = run_registry.resolve_run(app_id or app_name, sign_outputs=sign_outputs)

        if stage_key == "design" and payload_hint is not None:
            # ensure minted ids persisted to input for traceability
            self._persist_input(context, stage_key, json.dumps(payload_hint).encode("utf-8"))
        elif input_path is not None:
            self._persist_input(context, stage_key, input_path.read_bytes())

        processor = {
            "requirements": self.process_requirements,
            "design": self.process_design,
            "build": self.process_build,
            "test": self.process_test,
            "deploy": self.process_deploy,
            "operate": self.process_operate,
            "decision": self.process_decision,
        }[stage_key]

        if stage_key == "design":
            output_file = processor(context, payload_hint or {})
        elif stage_key == "requirements":
            output_file = processor(context, payload_hint or {})
        else:
            output_file = processor(context, input_path)

        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(output_file, output_path)

        signed = (
            list(context.signed_outputs_dir.glob(f"{output_file.name}.manifest.json"))
            if sign_outputs
            else []
        )
        transparency_index = (
            context.transparency_index if sign_outputs and context.transparency_index.exists() else None
        )

        if verify and sign_outputs and signed:
            self._verify_signatures(output_file, signed)

        bundle = None
        if stage_key == "decision":
            bundle = context.outputs_dir / "evidence_bundle.zip"
            if not bundle.exists():
                bundle = None

        if verbose:
            display_path = self._relative_display(output_file)
            print(
                f"Stage '{stage_key}' completed for app {context.app_id} run {context.run_id}: {display_path}"
            )

        return StageResult(
            stage=stage_key,
            app_id=context.app_id,
            run_id=context.run_id,
            output_file=output_file,
            outputs_dir=context.outputs_dir,
            signed=signed,
            transparency_index=transparency_index,
            bundle=bundle,
        )

    # Normalisation helpers -------------------------------------------------------
    def process_requirements(
        self, context: run_registry.RunContext, payload_hint: Mapping[str, Any]
    ) -> Path:
        records = []
        if payload_hint:
            records.extend(self._normalise_requirement_payload(payload_hint))
        input_file = context.inputs_dir / _INPUT_FILENAMES["requirements"]
        if input_file.exists():
            text = input_file.read_text(encoding="utf-8")
            if text.strip():
                reader = csv.DictReader(io.StringIO(text))
                for row in reader:
                    if any((value or "").strip() for value in row.values()):
                        records.append(self._normalise_requirement_row(row))
        anchor = self._compute_ssvc_anchor(records)
        document = {"requirements": records, "ssvc_anchor": anchor}
        return context.write_output("requirements.json", document)

    def process_design(
        self, context: run_registry.RunContext, payload_hint: Mapping[str, Any]
    ) -> Path:
        manifest = ensure_ids(dict(payload_hint)) if payload_hint else {}
        if not manifest:
            input_file = context.inputs_dir / _INPUT_FILENAMES["design"]
            if input_file.exists():
                manifest = ensure_ids(json.loads(input_file.read_text(encoding="utf-8")))
        components = manifest.get("components") if isinstance(manifest.get("components"), list) else []
        for component in components or []:
            if isinstance(component, MutableMapping):
                component.setdefault("component_id", self._mint_component_token(component.get("name")))
        manifest["design_risk_score"] = self._design_risk_score(manifest)
        manifest.setdefault("app_id", context.app_id)
        manifest.setdefault("app_name", manifest.get("app_name") or manifest.get("name") or context.app_id)
        return context.write_output("design.manifest.json", manifest)

    def process_build(self, context: run_registry.RunContext, input_path: Path | None) -> Path:
        if input_path is None:
            raise ValueError("Build stage requires an SBOM input")
        sbom_bytes = input_path.read_bytes()
        sbom = self._normalizer.load_sbom(sbom_bytes)
        components = [component.to_dict() for component in getattr(sbom, "components", [])]
        risk_flags = []
        for component in components:
            identifier = component.get("purl") or component.get("name")
            if identifier and "log4j" in str(identifier).lower():
                risk_flags.append({"purl": identifier, "reason": "log4j historical risk"})
        links = {}
        for name in ("sbom.json", "scanner.sarif", "provenance.slsa.json"):
            candidate = context.inputs_dir / name
            if candidate.exists():
                key = "sarif" if name == "scanner.sarif" else name.split(".")[0]
                links[key] = context.relative_to_outputs(candidate)
        design = self._safe_output(context, "design.manifest.json")
        app_id = design.get("app_id") or context.app_id
        score = 0.45 + 0.12 * len(risk_flags)
        report = {
            "app_id": app_id,
            "components_indexed": len(components),
            "risk_flags": risk_flags,
            "links": links,
            "build_risk_score": round(min(score, 0.99), 2),
        }
        return context.write_output("build.report.json", report)

    def process_test(self, context: run_registry.RunContext, input_path: Path | None) -> Path:
        findings = self._sarif_findings(context, input_path)
        severities = Counter(finding["severity"] for finding in findings)
        summary = {key: severities.get(key, 0) for key in ("critical", "high", "medium", "low")}
        drift = {"new_findings": 0}
        tests_payload = self._load_optional_json(context.inputs_dir / "tests-input.json")
        if not tests_payload and input_path and input_path.suffix.lower() == ".json" and "sarif" not in input_path.name:
            tests_payload = self._load_optional_json(input_path)
        if isinstance(tests_payload, Mapping):
            drift["new_findings"] = len(tests_payload.get("new_findings", []))
        coverage = tests_payload.get("coverage", 0) if isinstance(tests_payload, Mapping) else 0
        report = {
            "summary": summary,
            "drift": drift,
            "coverage": coverage,
            "test_risk_score": round(min(0.3 + 0.05 * summary["critical"] + 0.03 * summary["high"], 0.99), 2),
        }
        return context.write_output("test.report.json", report)

    def process_deploy(self, context: run_registry.RunContext, input_path: Path | None) -> Path:
        payload = self._load_deploy_payload(input_path)
        posture = self._analyse_posture(payload)
        digests = self._extract_provenance(context)
        requirements = self._safe_output(context, "requirements.json")
        evidence, failing_controls = self._deploy_evidence(requirements, posture, context)
        recommendations = self._marketplace_recommendations(failing_controls)
        score = 0.52
        if posture.get("public_buckets"):
            score += 0.18
        if posture.get("tls_policy") and "2016" in str(posture.get("tls_policy")):
            score += 0.05
        manifest = {
            "digests": digests,
            "posture": posture,
            "control_evidence": evidence,
            "deploy_risk_score": round(min(score, 0.99), 2),
            "marketplace_recommendations": recommendations,
        }
        return context.write_output("deploy.manifest.json", manifest)

    def process_operate(self, context: run_registry.RunContext, input_path: Path | None) -> Path:
        telemetry = self._load_optional_json(input_path) if input_path else None
        build_report = self._safe_output(context, "build.report.json")
        kev_feed = self._load_optional_json(Path("data/feeds/kev.json")) or {}
        epss_feed = self._load_optional_json(Path("data/feeds/epss.json")) or {}
        kev_hits = []
        epss_records = []
        risk_components = build_report.get("risk_flags", []) if isinstance(build_report, Mapping) else []
        if any("log4j" in str(flag.get("purl", "")).lower() for flag in risk_components if isinstance(flag, Mapping)):
            kev_hits.append("CVE-2021-44228")
            epss_records.append({"cve": "CVE-2021-44228", "score": 0.97})
        else:
            kev_hits.extend(kev_feed.get("top", []) if isinstance(kev_feed, Mapping) else [])
        pressure = 0.4
        if isinstance(telemetry, Mapping):
            latency = telemetry.get("latency_ms_p95")
            if isinstance(latency, (int, float)):
                pressure = max(pressure, min(0.95, latency / 650))
        design = self._safe_output(context, "design.manifest.json")
        service_name = design.get("app_name") or context.app_id
        snapshot = {
            "kev_hits": kev_hits,
            "epss": epss_records or epss_feed.get("top", []),
            "pressure_by_service": [{"service": service_name, "pressure": round(pressure, 2)}],
            "operate_risk_score": round(min(0.45 + 0.1 * len(kev_hits) + (0.05 if pressure >= 0.55 else 0), 0.99), 2),
        }
        return context.write_output("operate.snapshot.json", snapshot)

    def process_decision(self, context: run_registry.RunContext, input_path: Path | None) -> Path:
        stage_documents = self._collect_stage_inputs(context, input_path)
        deploy_manifest = stage_documents.get("deploy", {})
        operate_snapshot = stage_documents.get("operate", {})
        requirements = stage_documents.get("requirements", {})
        top_factors = self._decision_factors(stage_documents)
        compliance_rollup = self._compliance_rollup(requirements, deploy_manifest)
        failing_controls = [
            evidence.get("control")
            for evidence in deploy_manifest.get("control_evidence", [])
            if isinstance(evidence, Mapping) and evidence.get("result") == "fail"
        ]
        verdict = "DEFER" if failing_controls or operate_snapshot.get("kev_hits") else "ALLOW"
        confidence = round(min(0.7 + 0.06 * len(top_factors), 0.99), 2)
        recommendations = self._marketplace_recommendations(failing_controls)
        evidence_id = f"EV-{uuid.uuid4().hex[:10]}"
        decision = {
            "decision": verdict,
            "confidence_score": confidence,
            "top_factors": top_factors,
            "compliance_rollup": compliance_rollup,
            "marketplace_recommendations": recommendations,
            "evidence_id": evidence_id,
        }
        output = context.write_output("decision.json", decision)
        bundle = context.outputs_dir / "evidence_bundle.zip"
        self._write_evidence_bundle(stage_documents, bundle)
        manifest_payload = {
            "bundle": bundle.name,
            "documents": sorted(stage_documents.keys()),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "decision": output.name,
        }
        context.write_binary_output(
            "manifest.json",
            json.dumps(manifest_payload, indent=2, sort_keys=True).encode("utf-8"),
        )
        return output

    # Internal helpers -----------------------------------------------------------
    def _persist_input(self, context: run_registry.RunContext, stage: str, data: bytes) -> None:
        filename = _INPUT_FILENAMES[stage]
        context.save_input(filename, data)
        if stage == "test" and filename == "scanner.sarif":
            try:
                payload = json.loads(data.decode("utf-8"))
            except Exception:
                return
            if isinstance(payload, Mapping) and "results" not in payload:
                context.save_input("tests-input.json", payload)

    def _signing_available(self) -> bool:
        return bool(os.environ.get("FIXOPS_SIGNING_KEY") and os.environ.get("FIXOPS_SIGNING_KID"))

    def _verify_signatures(self, output_file: Path, envelopes: list[Path]) -> None:
        manifest = json.loads(output_file.read_text())
        for envelope_path in envelopes:
            envelope = json.loads(envelope_path.read_text())
            if not signing.verify_manifest(manifest, envelope):
                raise ValueError(f"Signature verification failed for {envelope_path}")
            print(f"Verified signature for {output_file.name} using {envelope_path.name}")

    def _load_design_payload(self, path: Path) -> Mapping[str, Any]:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".csv":
            reader = csv.DictReader(io.StringIO(text))
            rows = [row for row in reader if any((value or "").strip() for value in row.values())]
            return {"rows": rows, "columns": reader.fieldnames or []}
        return json.loads(text)

    def _load_requirements_payload(self, path: Path) -> Mapping[str, Any]:
        if path.suffix.lower() == ".json":
            return json.loads(path.read_text(encoding="utf-8"))
        reader = csv.DictReader(path.read_text(encoding="utf-8").splitlines())
        rows = [row for row in reader if any((value or "").strip() for value in row.values())]
        return {"requirements": rows}

    def _normalise_requirement_payload(self, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        items: Iterable[Any]
        if "requirements" in payload and isinstance(payload["requirements"], Iterable):
            items = payload["requirements"]  # type: ignore[assignment]
        else:
            items = [payload]
        records = []
        for item in items:
            if isinstance(item, Mapping):
                records.append(self._normalise_requirement_row(item))
        return records

    def _normalise_requirement_row(self, row: Mapping[str, Any]) -> dict[str, Any]:
        refs = self._split_refs(row.get("control_refs"))
        return {
            "requirement_id": str(row.get("requirement_id") or "REQ-UNKNOWN"),
            "feature": str(row.get("feature") or ""),
            "control_refs": refs,
            "data_class": str(row.get("data_class") or "unknown").lower(),
            "pii": self._as_bool(row.get("pii")),
            "internet_facing": self._as_bool(row.get("internet_facing")),
        }

    def _split_refs(self, value: Any) -> list[str]:
        if isinstance(value, str):
            return [token.strip() for token in value.split(";") if token.strip()]
        if isinstance(value, Iterable):
            return [str(token) for token in value if str(token).strip()]
        return []

    def _as_bool(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"true", "yes", "1"}
        return bool(value)

    def _compute_ssvc_anchor(self, records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        internet = any(record.get("internet_facing") for record in records)
        pii = any(record.get("pii") for record in records)
        if internet and pii:
            return {"stakeholder": "safety", "impact_tier": "critical"}
        if internet:
            return {"stakeholder": "mission", "impact_tier": "high"}
        if pii:
            return {"stakeholder": "safety", "impact_tier": "high"}
        return {"stakeholder": "maintenance", "impact_tier": "moderate"}

    def _mint_component_token(self, name: Any) -> str:
        token = str(name or "component").lower().replace(" ", "-")
        token = "".join(ch if ch.isalnum() or ch == "-" else "-" for ch in token).strip("-") or "component"
        return f"C-{token.split('-')[0]}"

    def _design_risk_score(self, payload: Mapping[str, Any]) -> float:
        components = payload.get("components") if isinstance(payload, Mapping) else []
        score = 0.5
        if isinstance(components, list):
            if any(str(item.get("exposure", "")).lower() == "internet" for item in components if isinstance(item, Mapping)):
                score += 0.2
            if any(bool(item.get("pii")) for item in components if isinstance(item, Mapping)):
                score += 0.08
        return round(min(score, 0.99), 2)

    def _sarif_findings(self, context: run_registry.RunContext, input_path: Path | None) -> list[dict[str, Any]]:
        try_paths = []
        if input_path is not None:
            try_paths.append(input_path)
        try_paths.append(context.inputs_dir / "scanner.sarif")
        findings: list[dict[str, Any]] = []
        for candidate in try_paths:
            if not candidate.exists():
                continue
            sarif = json.loads(candidate.read_text())
            for run in sarif.get("runs", []) or []:
                if not isinstance(run, Mapping):
                    continue
                for result in run.get("results", []) or []:
                    if not isinstance(result, Mapping):
                        continue
                    level = str(result.get("level") or "medium").lower()
                    severity = {
                        "error": "critical",
                        "warning": "high",
                        "note": "medium",
                    }.get(level, "low")
                    findings.append({"severity": severity})
        return findings

    def _load_deploy_payload(self, input_path: Path | None) -> Mapping[str, Any]:
        if input_path is None:
            raise ValueError("Deploy stage requires a Terraform plan or Kubernetes manifest")
        text = input_path.read_text()
        if input_path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(text)
            if isinstance(data, Mapping):
                return data
            if isinstance(data, list):
                return {"items": data}
            raise ValueError("Unsupported Kubernetes manifest format")
        return json.loads(text)

    def _analyse_posture(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        public_buckets: list[str] = []
        tls_policy = None
        if "resources" in payload:
            for resource in payload.get("resources", []) or []:
                if not isinstance(resource, Mapping):
                    continue
                rtype = resource.get("type")
                changes = resource.get("changes") if isinstance(resource.get("changes"), Mapping) else {}
                after = changes.get("after") if isinstance(changes.get("after"), Mapping) else {}
                if rtype == "aws_s3_bucket" and after.get("acl") == "public-read":
                    public_buckets.append(str(resource.get("name")))
                if rtype == "aws_lb_listener":
                    tls_policy = after.get("ssl_policy")
        items = payload.get("items") if isinstance(payload.get("items"), list) else []
        for item in items:
            if not isinstance(item, Mapping):
                continue
            metadata = item.get("metadata", {}) if isinstance(item.get("metadata"), Mapping) else {}
            name = metadata.get("name") or "resource"
            spec = item.get("spec", {}) if isinstance(item.get("spec"), Mapping) else {}
            annotations = metadata.get("annotations")
            if not isinstance(annotations, Mapping):
                annotations = {}
            if annotations.get("public") == "true" or spec.get("type") == "LoadBalancer":
                public_buckets.append(str(name))
        return {"public_buckets": public_buckets, "tls_policy": tls_policy}

    def _extract_provenance(self, context: run_registry.RunContext) -> list[str]:
        digests: list[str] = []
        provenance_path = context.inputs_dir / "provenance.slsa.json"
        if provenance_path.exists():
            provenance = json.loads(provenance_path.read_text())
            subjects = provenance.get("subject", []) if isinstance(provenance, Mapping) else []
            for subject in subjects:
                if not isinstance(subject, Mapping):
                    continue
                digest = subject.get("digest") if isinstance(subject.get("digest"), Mapping) else {}
                sha = digest.get("sha256")
                if sha:
                    digests.append(f"sha256:{sha}")
        return digests

    def _deploy_evidence(
        self,
        requirements: Mapping[str, Any],
        posture: Mapping[str, Any],
        context: run_registry.RunContext,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        evidence: list[dict[str, Any]] = []
        failing: list[str] = []
        controls = []
        for requirement in requirements.get("requirements", []) or []:
            if isinstance(requirement, Mapping):
                controls.extend(requirement.get("control_refs", []))
        controls = [str(control) for control in controls]
        tfplan_path = context.inputs_dir / "tfplan.json"
        evidence_path = context.relative_to_outputs(tfplan_path) if tfplan_path.exists() else ""
        for control in controls:
            result = "pass"
            source = "checks"
            if "AC-2" in control and posture.get("public_buckets"):
                result = "fail"
                source = "public_buckets"
            elif "AC-1" in control and not posture.get("tls_policy"):
                result = "partial"
                source = "tls_policy"
            record = {
                "control": control,
                "result": result,
                "source": source,
                "evidence_file": evidence_path,
            }
            evidence.append(record)
            if result == "fail":
                failing.append(control)
        return evidence, failing

    def _marketplace_recommendations(self, controls: Iterable[str]) -> list[dict[str, Any]]:
        try:
            from src.services.marketplace import get_recommendations
        except Exception:  # pragma: no cover - defensive import
            return []
        return get_recommendations(controls)

    def _safe_output(self, context: run_registry.RunContext, name: str) -> Mapping[str, Any]:
        try:
            data = context.load_output_json(name)
        except FileNotFoundError:
            return {}
        return data if isinstance(data, Mapping) else {}

    def _load_optional_json(self, path: Path | None) -> Any:
        if path is None or not path.exists():
            return {}
        try:
            return json.loads(path.read_text())
        except Exception:
            return {}

    def _collect_stage_inputs(self, context: run_registry.RunContext, input_path: Path | None) -> dict[str, Mapping[str, Any]]:
        documents: dict[str, Mapping[str, Any]] = {}
        if input_path and input_path.exists():
            payload = json.loads(input_path.read_text())
            for key, file_path in payload.items():
                if not isinstance(file_path, str):
                    continue
                target = Path(file_path)
                if target.exists():
                    documents[key] = json.loads(target.read_text())
        else:
            existing = run_registry.list_runs(context.app_id)
            previous = [run for run in existing if run != context.run_id]
            if previous:
                candidate = context.root / context.app_id / previous[-1] / "outputs"
                for name in (
                    "requirements.json",
                    "design.manifest.json",
                    "build.report.json",
                    "test.report.json",
                    "deploy.manifest.json",
                    "operate.snapshot.json",
                ):
                    path = candidate / name
                    if path.exists():
                        key = name.split(".")[0]
                        documents[key] = json.loads(path.read_text())
        # Ensure local outputs are also considered (current run for dependencies)
        for name in (
            "requirements.json",
            "design.manifest.json",
            "build.report.json",
            "test.report.json",
            "deploy.manifest.json",
            "operate.snapshot.json",
        ):
            path = context.outputs_dir / name
            if path.exists():
                key = name.split(".")[0]
                documents[key] = json.loads(path.read_text())
        return documents

    def _relative_display(self, path: Path) -> Path:
        try:
            return path.relative_to(Path.cwd())
        except ValueError:
            return path

    def _decision_factors(self, documents: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
        factors: list[dict[str, Any]] = []
        build_report = documents.get("build", {})
        operate = documents.get("operate", {})
        deploy = documents.get("deploy", {})
        highest = None
        summary = documents.get("test", {}).get("summary") if isinstance(documents.get("test"), Mapping) else {}
        if isinstance(summary, Mapping):
            for severity in ("critical", "high", "medium", "low"):
                if summary.get(severity):
                    highest = severity
                    break
        if highest:
            factors.append(
                {
                    "name": f"{highest.title()} severity tests",
                    "weight": 0.35,
                    "rationale": f"Detected {summary.get(highest)} {highest} findings in testing.",
                }
            )
        public_buckets = deploy.get("posture", {}).get("public_buckets", []) if isinstance(deploy, Mapping) else []
        if public_buckets:
            factors.append(
                {
                    "name": "Deployment posture gap",
                    "weight": 0.32,
                    "rationale": f"Public buckets detected: {', '.join(public_buckets)}.",
                }
            )
        kev_hits = operate.get("kev_hits", []) if isinstance(operate, Mapping) else []
        if kev_hits:
            factors.append(
                {
                    "name": "Active exploitation pressure",
                    "weight": 0.28,
                    "rationale": f"KEV catalogue has {len(kev_hits)} relevant entries.",
                }
            )
        if not factors:
            factors.append(
                {
                    "name": "Stable release",
                    "weight": 0.2,
                    "rationale": "No blockers detected across build, test, deploy or operate stages.",
                }
            )
        return factors

    def _compliance_rollup(
        self, requirements: Mapping[str, Any], deploy_manifest: Mapping[str, Any]
    ) -> dict[str, Any]:
        controls: dict[str, float] = {}
        frameworks: dict[str, list[float]] = {}
        evidence_lookup = {}
        for item in deploy_manifest.get("control_evidence", []) or []:
            if isinstance(item, Mapping):
                evidence_lookup[str(item.get("control"))] = item
        for requirement in requirements.get("requirements", []) or []:
            if not isinstance(requirement, Mapping):
                continue
            for control_ref in requirement.get("control_refs", []) or []:
                control_id = str(control_ref)
                evidence = evidence_lookup.get(control_id, {})
                result = evidence.get("result")
                coverage = 1.0 if result == "pass" else 0.0 if result == "fail" else 0.5
                controls[control_id] = coverage
                framework = control_id.split(":")[0] if ":" in control_id else "generic"
                frameworks.setdefault(framework, []).append(coverage)
        framework_rollup = []
        for framework, values in frameworks.items():
            coverage = round(sum(values) / len(values), 2)
            framework_rollup.append({"name": framework, "coverage": coverage})
        controls_list = [
            {"id": control_id, "coverage": round(coverage, 2)} for control_id, coverage in sorted(controls.items())
        ]
        return {"controls": controls_list, "frameworks": framework_rollup}

    def _write_evidence_bundle(self, documents: Mapping[str, Mapping[str, Any]], bundle_path: Path) -> None:
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(bundle_path, "w") as archive:
            for name, document in documents.items():
                if not isinstance(document, Mapping):
                    continue
                filename = {
                    "requirements": "requirements.json",
                    "design": "design.manifest.json",
                    "build": "build.report.json",
                    "test": "test.report.json",
                    "deploy": "deploy.manifest.json",
                    "operate": "operate.snapshot.json",
                }.get(name)
                if filename:
                    archive.writestr(filename, json.dumps(document, indent=2, sort_keys=True))


__all__ = ["StageRunner", "StageResult"]

