from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "suite-core"))

from core.sast_engine import SASTEngine  # noqa: E402


def main() -> int:
    target = REPO_ROOT / "suite-core" / "core" / "sast_engine.py"
    code = target.read_text(encoding="utf-8")
    engine = SASTEngine()
    result = engine.scan_code(code, str(target.relative_to(REPO_ROOT)))
    findings = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity.value,
            "cwe_id": f.cwe_id,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "snippet": f.snippet,
        }
        for f in result.findings
    ]
    print(json.dumps({"total_findings": result.total_findings, "findings": findings}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
