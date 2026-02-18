"""Command line runner for deterministic SSDLC simulations."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional

try:  # Optional dependency, only needed for YAML overlays
    import yaml  # type: ignore
except Exception:  # pragma: no cover - yaml is optional
    yaml = None  # type: ignore

BASE_DIR = Path(__file__).resolve().parent


class StageValidationError(Exception):
    """Raised when required inputs are missing or malformed."""


@dataclass(frozen=True)
class StageResult:
    filename: str
    payload: Mapping[str, Any]


def _ensure_inputs(stage: str, expected: Iterable[str]) -> Path:
    stage_dir = BASE_DIR / stage / "inputs"
    if not stage_dir.exists():
        raise StageValidationError(
            f"Stage '{stage}' inputs directory missing: {stage_dir}"
        )
    missing = [name for name in expected if not (stage_dir / name).exists()]
    if missing:
        raise StageValidationError(
            f"Stage '{stage}' missing required input files: {', '.join(missing)}"
        )
    return stage_dir


def _load_overlay(path: Optional[Path]) -> Mapping[str, Any]:
    if not path:
        return {}
    if not path.exists():
        raise StageValidationError(f"Overlay file not found: {path}")
    data: Mapping[str, Any]
    if path.suffix.lower() in {".yml", ".yaml"}:
        if yaml is None:
            raise StageValidationError(
                "PyYAML is required to use YAML overlays. Install pyyaml or provide JSON."
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    else:
        data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise StageValidationError(
            "Overlay must deserialize into an object (mapping/dict)."
        )
    return data


def _overlay_for_stage(overlay: Mapping[str, Any], stage: str) -> Mapping[str, Any]:
    """Return overlay section relevant for the requested stage."""

    if not overlay:
        return {}
    stages = (
        overlay.get("stages") if isinstance(overlay.get("stages"), Mapping) else None
    )
    if stages and isinstance(stages.get(stage), Mapping):
        base = overlay.copy()
        base.pop("stages", None)
        merged: MutableMapping[str, Any] = dict(base)
        return _deep_merge(merged, stages[stage])
    return overlay


def _deep_merge(
    target: MutableMapping[str, Any], overlay: Mapping[str, Any]
) -> MutableMapping[str, Any]:
    for key, value in overlay.items():
        if (
            key in target
            and isinstance(target[key], MutableMapping)
            and isinstance(value, Mapping)
        ):
            _deep_merge(target[key], value)  # type: ignore[arg-type]
        else:
            target[key] = value  # type: ignore[index]
    return target


def _design_stage(overlay: Mapping[str, Any]) -> StageResult:
    stage_dir = _ensure_inputs("design", ["design_context.csv"])
    context_file = stage_dir / "design_context.csv"
    with context_file.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        services = [{k: (v or "").strip() for k, v in row.items()} for row in reader]
    exposure_counts: Dict[str, int] = {}
    for entry in services:
        exposure = (entry.get("exposure") or "unknown").lower()
        exposure_counts[exposure] = exposure_counts.get(exposure, 0) + 1
    payload: MutableMapping[str, Any] = {
        "services": services,
        "risk_summary": {k: exposure_counts[k] for k in sorted(exposure_counts)},
    }
    if overlay:
        _deep_merge(payload, overlay)
    return StageResult("design_crosswalk.json", payload)


def _requirements_stage(overlay: Mapping[str, Any]) -> StageResult:
    stage_dir = _ensure_inputs("requirements", ["controls.json"])
    controls = json.loads((stage_dir / "controls.json").read_text(encoding="utf-8"))
    control_map = (
        controls.get("control_map", {}) if isinstance(controls, Mapping) else {}
    )
    plan = []
    for control_id in sorted(control_map):
        rules = control_map.get(control_id) or []
        status = "satisfied" if rules else "in_progress"
        plan.append({"id": control_id, "status": status, "rules": rules})
    payload: MutableMapping[str, Any] = {
        "controls": plan,
        "generated_from": "control_map",
    }
    if overlay:
        _deep_merge(payload, overlay)
    return StageResult("policy_plan.json", payload)


def _build_stage(overlay: Mapping[str, Any]) -> StageResult:
    stage_dir = _ensure_inputs("build", ["sbom.json"])
    sbom = json.loads((stage_dir / "sbom.json").read_text(encoding="utf-8"))
    components = sbom.get("components", []) if isinstance(sbom, Mapping) else []
    normalized = []
    for component in components:
        if not isinstance(component, Mapping):
            continue
        normalized.append(
            {
                "name": component.get("name"),
                "version": component.get("version"),
                "purl": component.get("purl"),
                "type": component.get("type"),
            }
        )
    payload: MutableMapping[str, Any] = {
        "component_count": len(normalized),
        "components": sorted(
            normalized,
            key=lambda item: (item.get("name") or "", item.get("version") or ""),
        ),
    }
    if overlay:
        _deep_merge(payload, overlay)
    return StageResult("component_index.json", payload)


def _test_stage(overlay: Mapping[str, Any]) -> StageResult:
    stage_dir = _ensure_inputs("test", ["scanner.sarif"])
    sarif = json.loads((stage_dir / "scanner.sarif").read_text(encoding="utf-8"))
    runs = sarif.get("runs", []) if isinstance(sarif, Mapping) else []
    severity: Dict[str, int] = {}
    tools = []
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        tool = run.get("tool", {}) if isinstance(run.get("tool"), Mapping) else {}
        driver = (
            tool.get("driver", {})
            if isinstance(tool.get("driver"), Mapping)
            else tool.get("driver")
        )
        if isinstance(driver, Mapping):
            name = driver.get("name")
            if name:
                tools.append(str(name))
        for result in (
            run.get("results", []) if isinstance(run.get("results"), list) else []
        ):
            if not isinstance(result, Mapping):
                continue
            level = str(result.get("level") or "none").lower()
            severity[level] = severity.get(level, 0) + 1
    payload: MutableMapping[str, Any] = {
        "tools": sorted(set(tools)),
        "severity_breakdown": {k: severity[k] for k in sorted(severity)},
    }
    if overlay:
        _deep_merge(payload, overlay)
    return StageResult("normalized_findings.json", payload)


def _deploy_stage(overlay: Mapping[str, Any]) -> StageResult:
    stage_dir = _ensure_inputs("deploy", ["iac.tfplan.json"])
    plan = json.loads((stage_dir / "iac.tfplan.json").read_text(encoding="utf-8"))
    open_ports: Dict[int, Dict[str, Any]] = {}
    changes = plan.get("resource_changes", []) if isinstance(plan, Mapping) else []
    for change in changes:
        if not isinstance(change, Mapping):
            continue
        after = (
            change.get("change", {}).get("after", {})
            if isinstance(change.get("change"), Mapping)
            else {}
        )
        ingress = after.get("ingress", []) if isinstance(after, Mapping) else []
        for rule in ingress:
            if not isinstance(rule, Mapping):
                continue
            port = rule.get("from_port")
            if port is None:
                continue
            open_ports[int(port)] = {
                "port": int(port),
                "protocol": rule.get("protocol", "tcp"),
                "cidr_blocks": rule.get("cidr_blocks", []),
            }
    payload: MutableMapping[str, Any] = {
        "open_ports": sorted(open_ports.values(), key=lambda item: item["port"]),
        "internet_exposed": any(
            rule.get("cidr_blocks") for rule in open_ports.values()
        ),
    }
    if overlay:
        _deep_merge(payload, overlay)
    return StageResult("iac_posture.json", payload)


def _operate_stage(overlay: Mapping[str, Any]) -> StageResult:
    stage_dir = _ensure_inputs("operate", ["kev.json", "epss.json"])
    kev = json.loads((stage_dir / "kev.json").read_text(encoding="utf-8"))
    epss = json.loads((stage_dir / "epss.json").read_text(encoding="utf-8"))
    kev_entries = kev.get("vulnerabilities", []) if isinstance(kev, Mapping) else []
    epss_scores = {}
    if isinstance(epss, Mapping):
        for item in epss.get("data", []) if isinstance(epss.get("data"), list) else []:
            if isinstance(item, Mapping) and item.get("cve"):
                epss_scores[str(item["cve"])] = item.get("epss")
    payload: MutableMapping[str, Any]
    if kev_entries:
        top = kev_entries[0]
        cve_id = (
            str(top.get("cveID"))
            if isinstance(top, Mapping) and top.get("cveID")
            else None
        )
        payload = {
            "kev": True,
            "cve": cve_id,
            "epss": epss_scores.get(cve_id) if cve_id else None,
            "priority": (
                "immediate" if cve_id and epss_scores.get(cve_id, 0) else "elevated"
            ),
        }
    else:
        payload = {"kev": False, "priority": "routine"}
    if overlay:
        _deep_merge(payload, overlay)
    return StageResult("exploitability.json", payload)


STAGES = {
    "design": _design_stage,
    "requirements": _requirements_stage,
    "build": _build_stage,
    "test": _test_stage,
    "deploy": _deploy_stage,
    "operate": _operate_stage,
}


def _write_output(out_dir: Path, result: StageResult) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    destination = out_dir / result.filename
    destination.write_text(
        json.dumps(result.payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate SSDLC simulation artifacts")
    parser.add_argument(
        "--stage",
        choices=sorted(STAGES.keys()) + ["all"],
        required=True,
        help="Lifecycle stage to generate or 'all' for every stage",
    )
    parser.add_argument(
        "--overlay",
        type=Path,
        default=None,
        help="Optional JSON or YAML overlay to merge into the generated payload",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Directory where generated files should be written",
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    overlay = _load_overlay(args.overlay)
    if args.stage == "all":
        outputs = {}
        for stage, runner in STAGES.items():
            stage_overlay = _overlay_for_stage(overlay, stage)
            try:
                result = runner(stage_overlay)
            except StageValidationError as exc:  # pragma: no cover
                parser.error(str(exc))
            destination = _write_output(args.out, result)
            outputs[stage] = str(destination)
        print(json.dumps({"stage": "all", "outputs": outputs}, indent=2))
        return 0

    stage_runner = STAGES[args.stage]
    try:
        result = stage_runner(_overlay_for_stage(overlay, args.stage))
    except StageValidationError as exc:  # pragma: no cover - defensive, handled below
        parser.error(str(exc))
    except FileNotFoundError as exc:
        parser.error(str(exc))
    destination = _write_output(args.out, result)
    print(json.dumps({"stage": args.stage, "output": str(destination)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
