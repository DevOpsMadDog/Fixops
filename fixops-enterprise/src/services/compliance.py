"""Compliance evaluation utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping


@dataclass
class ControlRollup:
    control_id: str
    framework: str
    status: str
    evidence: str | None = None
    passed: bool = False


class ComplianceEngine:
    """Derive compliance posture from normalized controls."""

    DEFAULT_FRAMEWORKS = ("iso_27001", "nist_ssdf")

    def evaluate(
        self,
        controls: Iterable[Mapping[str, Any]],
        frameworks: Iterable[str] | None = None,
        opa_rules: Iterable[Mapping[str, Any]] | None = None,
        opa_input: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        control_results = []
        framework_counts: Dict[str, Dict[str, int]] = {}
        for control in controls:
            control_id = str(control.get("id") or control.get("control") or "unknown")
            framework = str(control.get("framework") or control.get("framework_id") or "general")
            status = str(control.get("status") or "unknown").lower()
            evidence = control.get("evidence")
            passed = status in {"pass", "satisfied", "compliant"}
            control_results.append(
                ControlRollup(control_id=control_id, framework=framework, status=status, evidence=evidence, passed=passed)
            )
            bucket = framework_counts.setdefault(framework, {"total": 0, "pass": 0, "fail": 0})
            bucket["total"] += 1
            if passed:
                bucket["pass"] += 1
            elif status in {"fail", "failed", "gap", "non_compliant"}:
                bucket["fail"] += 1

        requested_frameworks = list(framework_counts.keys())
        if frameworks:
            requested_frameworks = list(frameworks)

        for name in requested_frameworks or list(self.DEFAULT_FRAMEWORKS):
            framework_counts.setdefault(name, {"total": 0, "pass": 0, "fail": 0})

        framework_rollups = {}
        for name, counts in framework_counts.items():
            total = max(1, counts["total"])
            framework_rollups[name] = {
                "total": counts["total"],
                "pass": counts["pass"],
                "fail": counts["fail"],
                "coverage": round(counts["pass"] / total, 3),
            }

        total_controls = len(control_results)
        passed_controls = sum(1 for roll in control_results if roll.passed)

        opa_result = None
        if opa_rules:
            opa_payload = opa_input or {"controls": [roll.__dict__ for roll in control_results]}
            opa_result = self.evaluate_opa(opa_rules, opa_payload)

        return {
            "controls": [roll.__dict__ for roll in control_results],
            "frameworks": framework_rollups,
            "coverage": {
                "total_controls": total_controls,
                "pass": passed_controls,
                "fail": total_controls - passed_controls,
                "coverage_rate": round(passed_controls / total_controls, 3) if total_controls else 0.0,
            },
            "opa": opa_result,
        }

    def evaluate_opa(self, rules: Iterable[Mapping[str, Any]], input_payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Attempt to run inline Rego rules using local OPA CLI if available."""

        import json
        import shutil
        import subprocess
        import tempfile

        if shutil.which("opa") is None:
            return {"status": "skipped", "reason": "opa binary not available"}

        evaluations = []
        for rule in rules:
            name = str(rule.get("name") or "policy")
            rego = rule.get("rego")
            if not isinstance(rego, str):
                continue
            with tempfile.NamedTemporaryFile("w", suffix=".rego", delete=False) as handle:
                handle.write(rego)
                handle.flush()
                result = subprocess.run(
                    ["opa", "eval", "data.policy.allow", "--format", "json", "--data", handle.name, "--input", "-"],
                    input=json.dumps(input_payload).encode("utf-8"),
                    capture_output=True,
                    check=False,
                )
            if result.returncode != 0:
                evaluations.append({"name": name, "status": "error", "stderr": result.stderr.decode("utf-8")})
            else:
                parsed = json.loads(result.stdout.decode("utf-8") or "{}")
                value = parsed.get("result", [{}])[0].get("expressions", [{}])[0].get("value")
                evaluations.append({"name": name, "status": "ok", "value": value})
        return {"status": "completed", "results": evaluations}

