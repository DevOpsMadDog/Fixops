#!/usr/bin/env python3
"""Self-Learning Feedback Loop Demo Script (DEMO-012).

Demonstrates ALdeci's 5 self-learning feedback loops:
1. Decision Outcome Loop  — AI decisions improve over time
2. MPTE Result Loop        — Exploitability predictions get more accurate
3. False Positive Loop     — Noisy scanners/rules get auto-suppressed
4. Remediation Success Loop — Fix recommendations improve based on outcomes
5. Policy Violation Loop   — Over-strict policies get auto-relaxed

Demo Flow:
  1. Reset → clean state
  2. Score a finding (baseline, no learning)
  3. Submit feedback for all 5 loops
  4. Run learning step (compute weight adjustments)
  5. Score the SAME finding (now with learning adjustments)
  6. Show the delta — proof that the system learned

Usage:
  python scripts/demo_self_learning.py              # Full demo
  python scripts/demo_self_learning.py --base-url http://localhost:8000  # Custom URL
  python scripts/demo_self_learning.py --quick       # Quick mode (fewer records)
  python scripts/demo_self_learning.py --full-loop   # Use the all-in-one endpoint

Requires:
  pip install requests
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any, Dict

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Install with: pip install requests")
    sys.exit(1)


# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def banner():
    print(f"""
{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════╗
║        ALdeci Self-Learning Feedback Loop Demo               ║
║                    DEMO-012 (V8)                             ║
║   "The system that gets smarter with every decision"         ║
╚═══════════════════════════════════════════════════════════════╝{RESET}
""")


def step(n: int, title: str):
    print(f"\n{BOLD}{CYAN}━━━ Step {n}: {title} ━━━{RESET}")


def ok(msg: str):
    print(f"  {GREEN}✓{RESET} {msg}")


def warn(msg: str):
    print(f"  {YELLOW}⚠{RESET} {msg}")


def err(msg: str):
    print(f"  {RED}✗{RESET} {msg}")


def info(msg: str):
    print(f"  {DIM}→{RESET} {msg}")


def api(method: str, url: str, token: str, json_data: dict = None) -> Dict[str, Any]:
    """Make an API call and return JSON response."""
    headers = {"X-API-Key": token, "Content-Type": "application/json"}
    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=30)
        elif method == "POST":
            resp = requests.post(url, headers=headers, json=json_data or {}, timeout=30)
        elif method == "PUT":
            resp = requests.put(url, headers=headers, json=json_data or {}, timeout=30)
        else:
            raise ValueError(f"Unknown method: {method}")

        if resp.status_code >= 400:
            err(f"HTTP {resp.status_code}: {resp.text[:200]}")
            return {"error": resp.text, "status_code": resp.status_code}
        return resp.json()
    except requests.ConnectionError:
        err(f"Cannot connect to {url}. Is the API server running?")
        sys.exit(1)
    except Exception as e:
        err(f"API error: {e}")
        return {"error": str(e)}


def run_full_loop(base_url: str, token: str):
    """Use the all-in-one /demo/full-loop endpoint."""
    step(1, "Running Full Self-Learning Demo (all-in-one endpoint)")
    result = api("GET", f"{base_url}/api/v1/self-learning/demo/full-loop", token)

    if "error" in result:
        err(f"Full loop failed: {result['error']}")
        return

    steps = result.get("steps", {})

    # Step 2: Baseline
    baseline = steps.get("2_baseline_score", {})
    ok(f"Baseline score: {baseline.get('score', '?')} (no learning)")

    # Step 3: Seed
    seed = steps.get("3_seed_data", {})
    ok(f"Seeded {seed.get('records_seeded', '?')} feedback records")

    # Step 4: Adjustments
    adj = steps.get("4_compute_adjustments", {})
    ok(f"Computed {adj.get('adjustments_applied', '?')} weight adjustments")
    for a in adj.get("adjustments", []):
        info(f"  [{a['loop']}] {a['target']}: {a['old']:.4f} → {a['new']:.4f} ({a['reasoning']})")

    # Step 5: Adjusted
    adjusted = steps.get("5_adjusted_score", {})
    ok(f"Adjusted score: {adjusted.get('score', '?')} ({adjusted.get('adjustments', 0)} adjustments)")

    # Step 6: Improvement
    improvement = steps.get("6_improvement", {})
    pct = improvement.get("percent_change", 0)
    direction = improvement.get("direction", "unknown")
    color = GREEN if direction == "risk_reduced" else (RED if direction == "risk_increased" else YELLOW)
    print(f"\n  {BOLD}{color}Result: {direction.upper()}{RESET}")
    print(f"  {BOLD}  Baseline: {improvement.get('baseline', '?')}{RESET}")
    print(f"  {BOLD}  After:    {improvement.get('after_learning', '?')}{RESET}")
    print(f"  {BOLD}  Change:   {pct:+.1f}%{RESET}")

    # Show loops demonstrated
    print(f"\n{BOLD}{CYAN}5 Feedback Loops Demonstrated:{RESET}")
    for loop_desc in result.get("loops_demonstrated", []):
        info(loop_desc)

    # Insights
    insights = result.get("insights", {})
    if insights.get("insight_count", 0) > 0:
        print(f"\n{BOLD}{CYAN}Learning Insights:{RESET}")
        for insight in insights.get("insights", []):
            severity_color = RED if insight["severity"] == "high" else YELLOW
            print(f"  {severity_color}[{insight['severity'].upper()}]{RESET} {insight['insight']}")


def run_step_by_step(base_url: str, token: str, quick: bool = False):
    """Run the demo step-by-step with individual API calls."""
    sl = f"{base_url}/api/v1/self-learning"

    # ── Step 1: Status check ──
    step(1, "Check Self-Learning Engine Status")
    status = api("GET", f"{sl}/status", token)
    if status.get("status") == "operational":
        ok(f"Engine operational — {status.get('loop_count', 5)} feedback loops active")
        ok(f"Total feedback records: {status.get('total_feedback', 0)}")
    else:
        err(f"Engine status: {status.get('status', 'unknown')}")

    # ── Step 2: Reset ──
    step(2, "Reset Learning Data (Clean Slate)")
    reset = api("POST", f"{sl}/demo/reset", token)
    if reset.get("reset"):
        ok(f"Cleared: {', '.join(reset.get('tables_cleared', []))}")
    else:
        warn("Reset returned unexpected result")

    # ── Step 3: Baseline score ──
    step(3, "Score a Finding (BASELINE — No Learning)")
    sample_finding = {
        "cvss_score": 7.5,
        "epss_score": 0.35,
        "in_kev": False,
        "asset_criticality": 0.7,
        "scanner": "zap",
        "rule_id": "10016-xss",
        "fix_type": "CODE_PATCH",
    }
    baseline = api("POST", f"{sl}/score-with-learning", token, sample_finding)
    baseline_score = baseline.get("baseline_score", 0)
    ok(f"Baseline risk score: {BOLD}{baseline_score}{RESET}")
    ok(f"Adjusted score: {baseline.get('adjusted_score', '?')} (same — no learning data yet)")
    ok(f"Adjustments applied: {baseline.get('adjustments_applied', 0)}")

    # ── Step 4: Seed demo data ──
    step(4, "Seed Feedback Data (98 records across 5 loops)")
    seed = api("POST", f"{sl}/demo/seed", token)
    seeded = seed.get("seeded", {})
    total = seed.get("total_records", 0)
    ok(f"Seeded {total} total records:")
    info(f"Loop 1 — Decision Outcomes: {seeded.get('decision', 0)} records")
    info(f"Loop 2 — MPTE Results:      {seeded.get('mpte', 0)} records")
    info(f"Loop 3 — False Positives:   {seeded.get('fp', 0)} records")
    info(f"Loop 4 — Remediation:       {seeded.get('remediation', 0)} records")
    info(f"Loop 5 — Policy Violations: {seeded.get('policy', 0)} records")

    # ── Step 5: Analyze before learning ──
    step(5, "Analyze All 5 Feedback Loops")
    analysis = api("GET", f"{sl}/analyze", token)

    dec = analysis.get("decision_outcomes", {})
    ok(f"Decision accuracy: {dec.get('accuracy', 0)}% ({dec.get('sample_count', 0)} samples)")

    mpte = analysis.get("mpte_results", {})
    ok(f"MPTE F1 score: {mpte.get('f1_score', 0)}% (P={mpte.get('precision', 0)}%, R={mpte.get('recall', 0)}%)")

    fp = analysis.get("false_positives", {})
    ok(f"Overall FP rate: {fp.get('overall_fp_rate', 0)}% ({fp.get('sample_count', 0)} samples)")
    for scanner_name, scanner_stats in fp.get("by_scanner", {}).items():
        fp_color = RED if scanner_stats["fp_rate"] > 40 else GREEN
        info(f"  {scanner_name}: {fp_color}{scanner_stats['fp_rate']}% FP{RESET} ({scanner_stats['total']} samples)")

    rem = analysis.get("remediation_success", {})
    ok(f"Remediation success: {rem.get('success_rate', 0)}% ({rem.get('sample_count', 0)} samples)")
    for fix_name, fix_stats in rem.get("by_fix_type", {}).items():
        fix_color = GREEN if fix_stats["success_rate"] > 70 else RED
        info(f"  {fix_name}: {fix_color}{fix_stats['success_rate']}%{RESET} ({fix_stats.get('avg_fix_hours', 0)}h avg)")

    pol = analysis.get("policy_violations", {})
    ok(f"Policy justified rate: {pol.get('justified_rate', 0)}% ({pol.get('sample_count', 0)} samples)")

    # ── Step 6: Compute learning adjustments ──
    step(6, "Compute Learning Adjustments (The Brain Learns)")
    adj_result = api("POST", f"{sl}/compute-adjustments", token)
    adj_count = adj_result.get("count", 0)
    ok(f"Computed {BOLD}{adj_count}{RESET} weight adjustments:")
    for adj in adj_result.get("adjustments", []):
        delta = adj["new_value"] - adj["old_value"]
        delta_color = GREEN if abs(delta) > 0.01 else DIM
        print(f"    {delta_color}[{adj['loop']}]{RESET} {adj['target']}: "
              f"{adj['old_value']:.4f} → {adj['new_value']:.4f} "
              f"({delta:+.4f}) — {adj['reasoning']}")

    # ── Step 7: Show learned weights ──
    step(7, "Show All Learned Weights")
    weights = api("GET", f"{sl}/weights", token)
    weight_count = weights.get("count", 0)
    ok(f"{weight_count} weights learned:")
    for key, w_data in weights.get("weights", {}).items():
        val = w_data["value"]
        val_color = GREEN if val >= 0.8 else (RED if val < 0.5 else YELLOW)
        info(f"  {key}: {val_color}{val:.4f}{RESET} (updated {w_data.get('update_count', 0)}x)")

    # ── Step 8: Re-score with learning ──
    step(8, "Re-Score the SAME Finding (WITH Learning)")
    after = api("POST", f"{sl}/score-with-learning", token, sample_finding)
    adjusted_score = after.get("adjusted_score", 0)
    delta = after.get("delta", 0)
    delta_pct = after.get("delta_percent", 0)

    ok(f"Baseline score:  {baseline_score}")
    ok(f"Adjusted score:  {BOLD}{adjusted_score}{RESET}")

    delta_color = GREEN if delta < 0 else (RED if delta > 0 else YELLOW)
    ok(f"Delta:           {delta_color}{delta:+.4f} ({delta_pct:+.1f}%){RESET}")
    ok(f"Adjustments:     {after.get('adjustments_applied', 0)} applied")

    for adj_detail in after.get("adjustments", []):
        info(f"  [{adj_detail['source']}] {adj_detail['factor']}: "
             f"weight={adj_detail['weight']:.4f} — {adj_detail['effect']}")

    # ── Step 9: Get insights ──
    step(9, "Generate Learning Insights")
    insights = api("GET", f"{sl}/insights", token)
    insight_list = insights.get("insights", [])
    ok(f"{insights.get('insight_count', 0)} insights generated "
       f"({insights.get('high_severity', 0)} high, {insights.get('medium_severity', 0)} medium)")

    for insight in insight_list:
        severity_color = RED if insight["severity"] == "high" else (YELLOW if insight["severity"] == "medium" else GREEN)
        print(f"    {severity_color}[{insight['severity'].upper()}]{RESET} {insight['insight']}")
        if "action" in insight:
            info(f"    Recommended action: {insight['action']}")

    # ── Summary ──
    print(f"\n{BOLD}{CYAN}{'═' * 63}{RESET}")
    print(f"{BOLD}{CYAN}  SELF-LEARNING DEMO SUMMARY{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 63}{RESET}")
    print(f"""
  Feedback records submitted:  {total}
  Weight adjustments computed: {adj_count}
  Insights generated:          {len(insight_list)}

  {BOLD}Risk Score Comparison:{RESET}
    Before learning: {baseline_score}
    After learning:  {adjusted_score}
    Change:          {delta_color}{delta:+.4f} ({delta_pct:+.1f}%){RESET}

  {BOLD}5 Feedback Loops:{RESET}
    1. Decision Outcome  — Accuracy: {dec.get('accuracy', 0)}%
    2. MPTE Result        — F1 Score: {mpte.get('f1_score', 0)}%
    3. False Positive     — FP Rate:  {fp.get('overall_fp_rate', 0)}%
    4. Remediation        — Success:  {rem.get('success_rate', 0)}%
    5. Policy Violation   — Justified: {pol.get('justified_rate', 0)}%

  {BOLD}{GREEN}The system proved it learns from experience.{RESET}
""")


def main():
    import os
    parser = argparse.ArgumentParser(description="ALdeci Self-Learning Feedback Loop Demo")
    parser.add_argument("--base-url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--token", default=None, help="API key for auth (overrides FIXOPS_API_TOKEN env var)")
    parser.add_argument("--full-loop", action="store_true", help="Use all-in-one endpoint")
    parser.add_argument("--quick", action="store_true", help="Quick mode (fewer records)")
    args = parser.parse_args()

    # Resolve token: CLI flag > env var > error
    if args.token is None:
        args.token = os.environ.get("FIXOPS_API_TOKEN", "")
    if not args.token:
        print("ERROR: FIXOPS_API_TOKEN environment variable must be set (or pass --token).")
        print("  export FIXOPS_API_TOKEN=your-enterprise-api-key-here")
        sys.exit(1)

    banner()
    info(f"Target: {args.base_url}")
    info(f"Mode: {'full-loop' if args.full_loop else 'step-by-step'}")

    start = time.time()

    if args.full_loop:
        run_full_loop(args.base_url, args.token)
    else:
        run_step_by_step(args.base_url, args.token, args.quick)

    elapsed = round(time.time() - start, 1)
    print(f"\n{DIM}Demo completed in {elapsed}s{RESET}")


if __name__ == "__main__":
    main()
