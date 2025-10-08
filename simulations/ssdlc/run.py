"""Run SSDLC stage simulations using canned fixtures."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent


def _design_stage(stage_dir: Path) -> Dict[str, Any]:
    inputs = stage_dir / "inputs"
    context_file = inputs / "design_context.csv"
    services: List[Dict[str, str]] = []
    with context_file.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            services.append({k: (v or "").strip() for k, v in row.items()})
    exposure_counts: Dict[str, int] = {}
    for entry in services:
        exposure = entry.get("exposure") or "unknown"
        exposure_counts[exposure] = exposure_counts.get(exposure, 0) + 1
    output = {
        "services": services,
        "risk_summary": exposure_counts,
    }
    _write_json(stage_dir / "outputs" / "design_crosswalk.json", output)
    return output


def _requirements_stage(stage_dir: Path) -> Dict[str, Any]:
    controls = json.loads((stage_dir / "inputs" / "controls.json").read_text(encoding="utf-8"))
    mapping = controls.get("control_map", {})
    plan = []
    for control_id, rules in mapping.items():
        status = "satisfied" if rules else "in_progress"
        plan.append({"id": control_id, "status": status})
    payload = {"controls": plan}
    _write_json(stage_dir / "outputs" / "policy_plan.json", payload)
    return payload


def _build_stage(stage_dir: Path) -> Dict[str, Any]:
    sbom = json.loads((stage_dir / "inputs" / "sbom.json").read_text(encoding="utf-8"))
    components = sbom.get("components", [])
    purls = [component.get("purl") for component in components if component.get("purl")]
    payload = {"component_count": len(components), "purls": purls}
    _write_json(stage_dir / "outputs" / "component_index.json", payload)
    return payload


def _test_stage(stage_dir: Path) -> Dict[str, Any]:
    sarif = json.loads((stage_dir / "inputs" / "scanner.sarif").read_text(encoding="utf-8"))
    runs = sarif.get("runs", [])
    severity: Dict[str, int] = {}
    tool_name = "unknown"
    for run in runs:
        tool = run.get("tool", {}).get("driver", {}).get("name")
        if tool:
            tool_name = tool
        for result in run.get("results", []):
            level = (result.get("level") or "none").lower()
            severity[level] = severity.get(level, 0) + 1
    payload = {"tool": tool_name, "severity_breakdown": severity}
    _write_json(stage_dir / "outputs" / "normalized_findings.json", payload)
    return payload


def _deploy_stage(stage_dir: Path) -> Dict[str, Any]:
    plan = json.loads((stage_dir / "inputs" / "iac.tfplan.json").read_text(encoding="utf-8"))
    open_ports: List[int] = []
    for change in plan.get("resource_changes", []):
        ingress_rules = change.get("change", {}).get("after", {}).get("ingress", [])
        for rule in ingress_rules:
            if "from_port" in rule:
                open_ports.append(int(rule.get("from_port")))
    payload = {"open_ports": sorted(set(open_ports)), "internet_exposed": bool(open_ports)}
    _write_json(stage_dir / "outputs" / "iac_posture.json", payload)
    return payload


def _operate_stage(stage_dir: Path) -> Dict[str, Any]:
    kev = json.loads((stage_dir / "inputs" / "kev.json").read_text(encoding="utf-8"))
    epss = json.loads((stage_dir / "inputs" / "epss.json").read_text(encoding="utf-8"))
    kev_entries = kev.get("vulnerabilities", [])
    epss_entries = {item.get("cve"): item.get("epss") for item in epss.get("data", [])}
    if not kev_entries:
        payload = {"kev": False, "priority": "routine"}
    else:
        cve_id = kev_entries[0].get("cveID")
        payload = {
            "cve": cve_id,
            "kev": True,
            "epss": epss_entries.get(cve_id),
            "priority": "immediate",
        }
    _write_json(stage_dir / "outputs" / "exploitability.json", payload)
    return payload


STAGE_DISPATCH = {
    "design": _design_stage,
    "requirements": _requirements_stage,
    "build": _build_stage,
    "test": _test_stage,
    "deploy": _deploy_stage,
    "operate": _operate_stage,
}


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SSDLC simulation fixtures")
    parser.add_argument("--stage", choices=STAGE_DISPATCH.keys(), required=True)
    parser.add_argument("--overlay", type=Path, help="Optional overlay file for reference", default=None)
    args = parser.parse_args()

    stage_dir = BASE_DIR / args.stage
    result = STAGE_DISPATCH[args.stage](stage_dir)
    if args.overlay and args.overlay.exists():
        overlay_path = args.overlay.resolve()
        print(f"Overlay reference: {overlay_path}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
