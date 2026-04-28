#!/usr/bin/env python3
"""
Render ALDECI self-scan JSON output as a static HTML page.

Usage:
    python scripts/render_self_scan_html.py self-scan-results.json > self-scan/index.html
    python scripts/render_self_scan_html.py self-scan-results.json --out self-scan/index.html

Input: SelfScanReport JSON (model_dump output from suite-core/core/self_scanner.py)
Output: Single-file HTML, no external JS dependencies, under 200 LOC, under 50 KB.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Grade colour map
# ---------------------------------------------------------------------------
_GRADE_COLOUR: Dict[str, str] = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}

_SEVERITY_COLOUR: Dict[str, str] = {
    "critical": "#dc2626",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#3b82f6",
    "info":     "#6b7280",
}

_CATEGORY_LABEL: Dict[str, str] = {
    "sast":        "SAST",
    "dependency":  "Dependency",
    "container":   "Container",
    "config":      "Config",
    "api_surface": "API Surface",
}


def _esc(value: Any) -> str:
    return html.escape(str(value) if value is not None else "")


def render(report: Dict[str, Any]) -> str:
    scan_date = report.get("scanned_at", "unknown")[:19].replace("T", " ") + " UTC"
    grade = report.get("grade", "?")
    risk_score = report.get("risk_score", 0)
    files_scanned = report.get("files_scanned", 0)
    lines_scanned = report.get("lines_scanned", 0)
    duration = report.get("duration_seconds", 0)
    scan_id = report.get("scan_id", "unknown")
    grade_colour = _GRADE_COLOUR.get(grade, "#6b7280")

    sev = report.get("findings_by_severity", {})
    cat = report.get("findings_by_category", {})

    findings: List[Dict] = report.get("findings", [])
    # Sort: critical > high > medium > low > info, then by title
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(
        findings,
        key=lambda f: (_sev_order.get(f.get("severity", "info"), 5), f.get("title", ""))
    )
    top20 = findings_sorted[:20]

    compliance_gaps: List[str] = report.get("compliance_gaps", [])
    remediation: List[str] = report.get("remediation_priorities", [])

    # --- severity summary badges ---
    sev_badges = ""
    for s in ("critical", "high", "medium", "low", "info"):
        count = sev.get(s, 0)
        colour = _SEVERITY_COLOUR[s]
        sev_badges += (
            f'<span class="badge" style="background:{colour}">'
            f'{_esc(s.upper())} {_esc(count)}</span> '
        )

    # --- category breakdown rows ---
    cat_rows = ""
    for key, label in _CATEGORY_LABEL.items():
        n = cat.get(key, 0)
        cat_rows += f"<tr><td>{_esc(label)}</td><td>{_esc(n)}</td></tr>\n"

    # --- top 20 findings table ---
    finding_rows = ""
    for f in top20:
        sev_val = f.get("severity", "info")
        colour = _SEVERITY_COLOUR.get(sev_val, "#6b7280")
        file_info = _esc(f.get("file_path") or "")
        line_info = f":{f['line_number']}" if f.get("line_number") else ""
        cwe = f.get("cwe_id") or ""
        owasp = f.get("owasp") or ""
        finding_rows += (
            f'<tr>'
            f'<td><span class="badge" style="background:{colour}">{_esc(sev_val.upper())}</span></td>'
            f'<td>{_esc(_CATEGORY_LABEL.get(f.get("category",""), f.get("category","")))}</td>'
            f'<td>{_esc(f.get("title",""))}</td>'
            f'<td class="mono">{file_info}{_esc(line_info)}</td>'
            f'<td>{_esc(cwe)}</td>'
            f'<td>{_esc(owasp)}</td>'
            f'</tr>\n'
        )

    # --- remediation priorities ---
    remed_items = "".join(f"<li>{_esc(p)}</li>\n" for p in remediation[:10])
    # --- compliance gaps ---
    gap_items = "".join(f"<li>{_esc(g)}</li>\n" for g in compliance_gaps[:10])

    total_findings = len(findings)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ALDECI Self-Scan Dashboard</title>
<style>
  body{{font-family:system-ui,sans-serif;margin:0;padding:0;background:#0f172a;color:#e2e8f0}}
  header{{background:#1e293b;padding:1.5rem 2rem;border-bottom:2px solid #334155}}
  header h1{{margin:0;font-size:1.5rem;letter-spacing:.05em;color:#f8fafc}}
  header p{{margin:.25rem 0 0;color:#94a3b8;font-size:.85rem}}
  .container{{max-width:1100px;margin:0 auto;padding:2rem}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}}
  .card{{background:#1e293b;border-radius:.5rem;padding:1.25rem;border:1px solid #334155}}
  .card .label{{font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:#64748b;margin-bottom:.4rem}}
  .card .value{{font-size:2rem;font-weight:700}}
  .grade{{font-size:3rem;font-weight:900}}
  .badge{{display:inline-block;padding:.15rem .5rem;border-radius:.25rem;font-size:.75rem;font-weight:600;color:#fff;margin:.1rem}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  th{{text-align:left;padding:.6rem .75rem;background:#1e293b;color:#94a3b8;font-weight:600;border-bottom:1px solid #334155}}
  td{{padding:.5rem .75rem;border-bottom:1px solid #1e293b}}
  tr:nth-child(even) td{{background:#0f172a}}
  tr:hover td{{background:#1e293b}}
  .mono{{font-family:monospace;font-size:.78rem;word-break:break-all}}
  section{{margin-bottom:2rem}}
  section h2{{font-size:1rem;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.07em;margin-bottom:.75rem}}
  ul{{padding-left:1.25rem;color:#cbd5e1;font-size:.87rem;line-height:1.7}}
  .footer{{text-align:center;color:#475569;font-size:.78rem;padding:2rem 0 1rem}}
  .sev-summary{{margin-bottom:1rem}}
</style>
</head>
<body>
<header>
  <h1>ALDECI Self-Scan Dashboard</h1>
  <p>ALDECI scans its own codebase — no demo data, real findings, public reference.
     Scan ID: <code>{_esc(scan_id)}</code></p>
</header>
<div class="container">

  <div class="grid">
    <div class="card">
      <div class="label">Security Grade</div>
      <div class="value grade" style="color:{grade_colour}">{_esc(grade)}</div>
    </div>
    <div class="card">
      <div class="label">Risk Score (lower is better)</div>
      <div class="value">{_esc(round(risk_score, 1))}<span style="font-size:1rem;color:#64748b">/100</span></div>
    </div>
    <div class="card">
      <div class="label">Total Findings</div>
      <div class="value">{_esc(total_findings)}</div>
    </div>
    <div class="card">
      <div class="label">Files Scanned</div>
      <div class="value">{_esc(files_scanned)}</div>
    </div>
    <div class="card">
      <div class="label">Lines Scanned</div>
      <div class="value">{_esc(lines_scanned)}</div>
    </div>
    <div class="card">
      <div class="label">Scan Duration</div>
      <div class="value">{_esc(round(duration, 1))}<span style="font-size:1rem;color:#64748b">s</span></div>
    </div>
  </div>

  <section>
    <h2>Scan Date</h2>
    <p id="scan_date" style="color:#e2e8f0;font-size:1rem">{_esc(scan_date)}</p>
  </section>

  <section>
    <h2>Findings by Severity</h2>
    <div class="sev-summary">{sev_badges}</div>
  </section>

  <section>
    <h2>Findings by Category</h2>
    <table>
      <thead><tr><th>Category</th><th>Count</th></tr></thead>
      <tbody>{cat_rows}</tbody>
    </table>
  </section>

  <section>
    <h2>Top 20 Findings</h2>
    <div id="top_findings_table">
    <table>
      <thead>
        <tr>
          <th>Severity</th><th>Category</th><th>Title</th>
          <th>File</th><th>CWE</th><th>OWASP</th>
        </tr>
      </thead>
      <tbody>{finding_rows}</tbody>
    </table>
    </div>
  </section>

  <section>
    <h2>Remediation Priorities</h2>
    <ul>{remed_items if remed_items else "<li>None identified.</li>"}</ul>
  </section>

  <section>
    <h2>Compliance Gaps</h2>
    <ul>{gap_items if gap_items else "<li>None identified.</li>"}</ul>
  </section>

</div>
<div class="footer">
  Generated by ALDECI Self-Scan Dogfooding Engine &mdash;
  <a href="https://devopsmaddog.github.io/Fixops/self-scan/" style="color:#38bdf8">
    devopsmaddog.github.io/Fixops/self-scan/
  </a>
  &mdash; refreshed on every push to <code>features/intermediate-stage</code>.
</div>
</body>
</html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Render ALDECI self-scan JSON to HTML")
    parser.add_argument("input", help="Path to self-scan-results.json")
    parser.add_argument("--out", help="Output file path (default: stdout)")
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        print(f"ERROR: input file not found: {path}", file=sys.stderr)
        sys.exit(1)

    report = json.loads(path.read_text(encoding="utf-8"))
    html_output = render(report)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html_output, encoding="utf-8")
        size_kb = len(html_output.encode()) / 1024
        print(f"Written {out_path} ({size_kb:.1f} KB)", file=sys.stderr)
    else:
        print(html_output)


if __name__ == "__main__":
    main()
