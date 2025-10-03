import sys
from pathlib import Path


def test_playbook_report_includes_compliance_and_regression():
    script_dir = Path(__file__).resolve().parents[1] / "fixops-blended-enterprise" / "scripts"
    sys.path.insert(0, str(script_dir))
    try:
        playbook = __import__("run_real_cve_playbook")
    finally:
        sys.path.pop(0)

    runs = playbook.generate_playbook_runs()
    report = playbook.render_playbook_report(runs)

    assert "Regression Confidence: 62.0% (failed, 4 similar cases)" in report
    assert "Regression Confidence: 88.0% (passed, 18 similar cases)" in report
    assert "Compliance Coverage: 0.0% (0/2 frameworks)" in report
    assert "Failed Frameworks: PCI DSS, SOC2" in report
    assert "Compliance Coverage: 100.0% (2/2 frameworks)" in report
    assert "Failed Frameworks: none" in report
