from __future__ import annotations

import json

from fixops import cli as fixops_cli
from fixops.demo_runner import generate_showcase


def test_generate_showcase_includes_stage_breakdown():
    snapshot = generate_showcase(mode="demo")

    assert snapshot["mode"] == "demo"
    assert "inputs" in snapshot
    assert "pipeline" in snapshot
    assert "integrations" in snapshot

    sbom_metrics = snapshot["inputs"]["sbom"]["metrics"]
    assert sbom_metrics["component_count"] > 0

    policy_summary = snapshot["integrations"]["policy_automation"]
    assert policy_summary["action_count"] >= 0


def test_cli_showcase_json_output(capsys):
    parser = fixops_cli.build_parser()
    args = parser.parse_args(["showcase", "--mode", "demo", "--json"])

    exit_code = args.func(args)
    assert exit_code == 0

    captured = capsys.readouterr().out
    payload = json.loads(captured)
    assert payload["mode"] == "demo"
    assert "pipeline" in payload
