from pathlib import Path

from fixops.demo_runner import run_demo_pipeline


def test_run_demo_pipeline_demo_mode(tmp_path: Path) -> None:
    output_path = tmp_path / "demo.json"
    result, summary = run_demo_pipeline(mode="demo", output_path=output_path, include_summary=False)
    assert output_path.exists()
    assert "FixOps Demo mode summary:" == summary[0]
    assert result.get("severity_overview")


def test_run_demo_pipeline_enterprise_mode(tmp_path: Path) -> None:
    output_path = tmp_path / "enterprise.json"
    result, summary = run_demo_pipeline(
        mode="enterprise",
        output_path=output_path,
        include_summary=False,
    )
    assert output_path.exists()
    assert "FixOps Enterprise mode summary:" == summary[0]
    assert result.get("pricing_summary")
