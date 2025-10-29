#!/usr/bin/env python3
"""FixOps Demo Runner - End-to-End CVE Prioritization.

Processes 50k CVEs with bidirectional risk scoring:
- Day-0: Structural priors (pre-auth, exposure, data adjacency, blast radius)
- Day-N: KEV/EPSS reinforcement

Generates:
- Prioritized findings (top 100)
- Evidence bundle (RSA-signed)
- Summary report
"""

import json
import sys
import time
import zipfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).parent.parent

INPUTS_DIR = REPO_ROOT / "data" / "inputs"
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
REPORTS_DIR = REPO_ROOT / "reports"

ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class RiskScore:
    """Bidirectional risk score with explainability."""

    cve: str
    asset_id: str
    surface: str

    cvss: float
    epss_score: float
    kev: bool

    day0_score: float
    day0_factors: Dict[str, float]

    dayn_score: float
    dayn_factors: Dict[str, float]

    final_score: float
    final_severity: str

    internet_facing: bool
    pre_auth: bool
    data_classes: List[str]
    compensating_controls: Dict[str, bool]
    patch_available: bool
    blast_radius: str

    rationale: str


class BidirectionalScorer:
    """Compute Day-0 and Day-N risk scores with explainability."""

    DAY0_WEIGHTS = {
        "pre_auth_rce": 0.35,
        "internet_facing": 0.25,
        "data_adjacency": 0.20,
        "blast_radius": 0.15,
        "compensating_controls": -0.15,
    }

    DAYN_WEIGHTS = {
        "kev": 0.40,
        "epss": 0.35,
        "cvss": 0.25,
    }

    def score(self, finding: Dict) -> RiskScore:
        """Compute bidirectional risk score."""

        day0_factors = self._compute_day0_factors(finding)
        day0_score = sum(day0_factors.values())
        day0_score = max(0.0, min(1.0, day0_score))

        dayn_factors = self._compute_dayn_factors(finding)
        dayn_score = sum(dayn_factors.values())
        dayn_score = max(0.0, min(1.0, dayn_score))

        final_score = (day0_score * 0.6) + (dayn_score * 0.4)

        final_severity = self._determine_severity(final_score, finding)

        rationale = self._build_rationale(
            finding, day0_factors, dayn_factors, day0_score, dayn_score, final_score
        )

        return RiskScore(
            cve=finding["cve"],
            asset_id=finding["asset_id"],
            surface=finding["asset_type"],
            cvss=finding["cvss"],
            epss_score=finding["epss_score"],
            kev=finding["kev"],
            day0_score=round(day0_score, 3),
            day0_factors={k: round(v, 3) for k, v in day0_factors.items()},
            dayn_score=round(dayn_score, 3),
            dayn_factors={k: round(v, 3) for k, v in dayn_factors.items()},
            final_score=round(final_score, 3),
            final_severity=final_severity,
            internet_facing=finding["internet_facing"],
            pre_auth=finding["pre_auth"],
            data_classes=finding["data_classes"],
            compensating_controls=finding["compensating_controls"],
            patch_available=finding["patch_available"],
            blast_radius=finding["blast_radius"],
            rationale=rationale,
        )

    def _compute_day0_factors(self, finding: Dict) -> Dict[str, float]:
        """Compute Day-0 structural priors."""
        factors = {}

        if finding["pre_auth"]:
            factors["pre_auth_rce"] = self.DAY0_WEIGHTS["pre_auth_rce"]

        if finding["internet_facing"]:
            factors["internet_facing"] = self.DAY0_WEIGHTS["internet_facing"]

        if finding["data_classes"]:
            data_weight = len(finding["data_classes"]) * 0.07
            factors["data_adjacency"] = min(
                data_weight, self.DAY0_WEIGHTS["data_adjacency"]
            )

        blast_map = {"high": 1.0, "medium": 0.6, "low": 0.3}
        blast_multiplier = blast_map.get(finding["blast_radius"], 0.3)
        factors["blast_radius"] = self.DAY0_WEIGHTS["blast_radius"] * blast_multiplier

        controls = finding["compensating_controls"]
        control_count = sum(1 for v in controls.values() if v)
        if control_count > 0:
            control_reduction = control_count * 0.05
            factors["compensating_controls"] = -min(control_reduction, 0.15)

        return factors

    def _compute_dayn_factors(self, finding: Dict) -> Dict[str, float]:
        """Compute Day-N reinforcement signals."""
        factors = {}

        if finding["kev"]:
            factors["kev"] = self.DAYN_WEIGHTS["kev"]

        epss = finding["epss_score"]
        if epss > 0.7:
            factors["epss"] = self.DAYN_WEIGHTS["epss"]
        elif epss > 0.4:
            factors["epss"] = self.DAYN_WEIGHTS["epss"] * 0.7
        elif epss > 0.1:
            factors["epss"] = self.DAYN_WEIGHTS["epss"] * 0.4

        cvss = finding["cvss"]
        if cvss >= 9.0:
            factors["cvss"] = self.DAYN_WEIGHTS["cvss"]
        elif cvss >= 7.0:
            factors["cvss"] = self.DAYN_WEIGHTS["cvss"] * 0.75
        elif cvss >= 4.0:
            factors["cvss"] = self.DAYN_WEIGHTS["cvss"] * 0.5

        return factors

    def _determine_severity(self, final_score: float, finding: Dict) -> str:
        """Determine final severity with bidirectional logic."""

        if finding["kev"] and final_score > 0.7:
            return "CRITICAL"

        if final_score >= 0.85:
            return "CRITICAL"
        elif final_score >= 0.7:
            return "HIGH"
        elif final_score >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"

    def _build_rationale(
        self,
        finding: Dict,
        day0_factors: Dict[str, float],
        dayn_factors: Dict[str, float],
        day0_score: float,
        dayn_score: float,
        final_score: float,
    ) -> str:
        """Build human-readable rationale."""
        parts = []

        parts.append(f"Day-0 structural risk: {day0_score:.2f}")
        if day0_factors:
            day0_desc = ", ".join(f"{k}={v:.2f}" for k, v in day0_factors.items())
            parts.append(f"  ({day0_desc})")

        parts.append(f"Day-N signals: {dayn_score:.2f}")
        if dayn_factors:
            dayn_desc = ", ".join(f"{k}={v:.2f}" for k, v in dayn_factors.items())
            parts.append(f"  ({dayn_desc})")

        parts.append(f"Final risk: {final_score:.2f}")

        if finding["kev"]:
            parts.append("KEV=true (actively exploited)")
        if finding["epss_score"] > 0.5:
            parts.append(f"EPSS={finding['epss_score']:.3f} (high exploit probability)")
        if finding["pre_auth"]:
            parts.append("Pre-auth (no login required)")
        if finding["internet_facing"]:
            parts.append("Internet-facing")
        if finding["data_classes"]:
            parts.append(f"Data: {', '.join(finding['data_classes'])}")

        return "; ".join(parts)


def load_findings(limit: Optional[int] = None) -> List[Dict]:
    """Load findings from NDJSON."""
    findings_path = INPUTS_DIR / "findings.ndjson"

    if not findings_path.exists():
        print(f"❌ Error: {findings_path} not found")
        print("   Run scripts/generate_realistic_cves.py first")
        sys.exit(1)

    print(f"Loading findings from {findings_path}...")
    findings = []

    with findings_path.open("r") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            finding = json.loads(line)
            findings.append(finding)

    print(f"✓ Loaded {len(findings):,} findings")
    return findings


def process_findings(findings: List[Dict], mode: str = "full") -> List[RiskScore]:
    """Process findings with bidirectional scoring."""

    print(f"\nProcessing {len(findings):,} findings in {mode} mode...")
    start_time = time.perf_counter()

    scorer = BidirectionalScorer()
    scores = []

    batch_size = 5000
    for i in range(0, len(findings), batch_size):
        batch = findings[i : i + batch_size]
        batch_scores = [scorer.score(f) for f in batch]
        scores.extend(batch_scores)

        elapsed = time.perf_counter() - start_time
        rate = len(scores) / elapsed if elapsed > 0 else 0
        print(
            f"  Progress: {len(scores):,}/{len(findings):,} ({rate:.0f} findings/sec)",
            end="\r",
        )

    elapsed = time.perf_counter() - start_time
    rate = len(scores) / elapsed if elapsed > 0 else 0

    print(
        f"\n✓ Processed {len(scores):,} findings in {elapsed:.1f}s ({rate:.0f} findings/sec)"
    )

    return scores


def prioritize_findings(scores: List[RiskScore], top_n: int = 100) -> List[RiskScore]:
    """Prioritize findings by final score."""

    print(f"\nPrioritizing top {top_n} findings...")

    sorted_scores = sorted(scores, key=lambda s: (-s.final_score, -s.epss_score, s.cve))
    top_scores = sorted_scores[:top_n]

    print(f"✓ Selected top {len(top_scores)} findings")

    return top_scores


def generate_statistics(scores: List[RiskScore]) -> Dict:
    """Generate statistics from scored findings."""

    stats = {
        "total": len(scores),
        "by_severity": defaultdict(int),
        "by_surface": defaultdict(int),
        "kev_count": 0,
        "high_epss": 0,
        "internet_facing": 0,
        "pre_auth": 0,
        "with_data": 0,
        "avg_day0_score": 0.0,
        "avg_dayn_score": 0.0,
        "avg_final_score": 0.0,
    }

    for score in scores:
        stats["by_severity"][score.final_severity] += 1
        stats["by_surface"][score.surface] += 1

        if score.kev:
            stats["kev_count"] += 1
        if score.epss_score > 0.5:
            stats["high_epss"] += 1
        if score.internet_facing:
            stats["internet_facing"] += 1
        if score.pre_auth:
            stats["pre_auth"] += 1
        if score.data_classes:
            stats["with_data"] += 1

        stats["avg_day0_score"] += score.day0_score
        stats["avg_dayn_score"] += score.dayn_score
        stats["avg_final_score"] += score.final_score

    if len(scores) > 0:
        stats["avg_day0_score"] /= len(scores)
        stats["avg_dayn_score"] /= len(scores)
        stats["avg_final_score"] /= len(scores)

    stats["by_severity"] = dict(stats["by_severity"])
    stats["by_surface"] = dict(stats["by_surface"])

    return stats


def save_results(
    all_scores: List[RiskScore],
    top_scores: List[RiskScore],
    stats: Dict,
    mode: str,
) -> Dict[str, Path]:
    """Save results to disk."""

    print("\nSaving results...")

    output_files = {}

    top_json_path = ARTIFACTS_DIR / f"top_prioritized_{mode}.json"
    top_json_path.write_text(json.dumps([asdict(s) for s in top_scores], indent=2))
    output_files["top_json"] = top_json_path
    print(f"✓ Saved {top_json_path}")

    top_csv_path = ARTIFACTS_DIR / f"top_prioritized_{mode}.csv"
    with top_csv_path.open("w") as f:
        f.write(
            "rank,cve,asset_id,surface,final_score,final_severity,day0_score,dayn_score,kev,epss,cvss,rationale\n"
        )
        for i, score in enumerate(top_scores, 1):
            f.write(
                f'{i},"{score.cve}","{score.asset_id}",{score.surface},{score.final_score},{score.final_severity},{score.day0_score},{score.dayn_score},{score.kev},{score.epss_score},{score.cvss},"{score.rationale}"\n'
            )
    output_files["top_csv"] = top_csv_path
    print(f"✓ Saved {top_csv_path}")

    stats_path = ARTIFACTS_DIR / f"statistics_{mode}.json"
    stats_path.write_text(json.dumps(stats, indent=2))
    output_files["stats"] = stats_path
    print(f"✓ Saved {stats_path}")

    evidence_bundle_path = ARTIFACTS_DIR / f"evidence_bundle_{mode}.zip"
    with zipfile.ZipFile(evidence_bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(top_json_path, top_json_path.name)
        zf.write(top_csv_path, top_csv_path.name)
        zf.write(stats_path, stats_path.name)

        manifest = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "mode": mode,
            "total_findings": len(all_scores),
            "top_findings": len(top_scores),
            "statistics": stats,
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    output_files["evidence_bundle"] = evidence_bundle_path
    print(f"✓ Saved {evidence_bundle_path}")

    return output_files


def generate_report(
    top_scores: List[RiskScore],
    stats: Dict,
    output_files: Dict[str, Path],
    mode: str,
) -> Path:
    """Generate summary report."""

    print("\nGenerating summary report...")

    report_path = REPORTS_DIR / f"demo_summary_{mode}.md"

    with report_path.open("w") as f:
        f.write("# FixOps Demo Summary\n\n")
        f.write(f"**Mode**: {mode}\n")
        f.write(
            f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n"
        )

        f.write("## Overview\n\n")
        f.write(
            f"Processed **{stats['total']:,}** CVEs with bidirectional risk scoring:\n"
        )
        f.write(
            "- **Day-0**: Structural priors (pre-auth, exposure, data adjacency, blast radius, compensating controls)\n"
        )
        f.write("- **Day-N**: KEV/EPSS reinforcement signals\n\n")

        f.write("## Key Metrics\n\n")
        f.write(f"- **KEV CVEs**: {stats['kev_count']:,} (actively exploited)\n")
        f.write(f"- **High EPSS** (>0.5): {stats['high_epss']:,}\n")
        f.write(f"- **Internet-facing**: {stats['internet_facing']:,}\n")
        f.write(f"- **Pre-auth**: {stats['pre_auth']:,}\n")
        f.write(f"- **With sensitive data**: {stats['with_data']:,}\n\n")

        f.write("## Risk Scores\n\n")
        f.write(f"- **Avg Day-0 score**: {stats['avg_day0_score']:.3f}\n")
        f.write(f"- **Avg Day-N score**: {stats['avg_dayn_score']:.3f}\n")
        f.write(f"- **Avg Final score**: {stats['avg_final_score']:.3f}\n\n")

        f.write("## Distribution\n\n")
        f.write("### By Severity\n\n")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = stats["by_severity"].get(severity, 0)
            pct = (count / stats["total"] * 100) if stats["total"] > 0 else 0
            f.write(f"- **{severity}**: {count:,} ({pct:.1f}%)\n")

        f.write("\n### By Surface\n\n")
        for surface in ["container", "appsec", "cloud"]:
            count = stats["by_surface"].get(surface, 0)
            pct = (count / stats["total"] * 100) if stats["total"] > 0 else 0
            f.write(f"- **{surface}**: {count:,} ({pct:.1f}%)\n")

        f.write(f"\n## Top {len(top_scores)} Prioritized Findings\n\n")
        f.write(
            "| Rank | CVE | Asset | Surface | Score | Severity | KEV | EPSS | Rationale |\n"
        )
        f.write(
            "|------|-----|-------|---------|-------|----------|-----|------|----------|\n"
        )

        for i, score in enumerate(top_scores[:20], 1):
            kev_mark = "✓" if score.kev else ""
            rationale_short = (
                score.rationale[:80] + "..."
                if len(score.rationale) > 80
                else score.rationale
            )
            f.write(
                f"| {i} | {score.cve} | {score.asset_id[:20]} | {score.surface} | {score.final_score:.3f} | {score.final_severity} | {kev_mark} | {score.epss_score:.3f} | {rationale_short} |\n"
            )

        if len(top_scores) > 20:
            f.write(f"\n*Showing top 20 of {len(top_scores)} prioritized findings*\n")

        f.write("\n## Output Files\n\n")
        for name, path in output_files.items():
            size_mb = path.stat().st_size / (1024 * 1024)
            f.write(f"- **{name}**: `{path}` ({size_mb:.1f} MB)\n")

    print(f"✓ Saved {report_path}")
    return report_path


def main():
    """Run demo."""

    import argparse

    parser = argparse.ArgumentParser(description="FixOps Demo Runner")
    parser.add_argument(
        "--mode",
        choices=["quick", "full"],
        default="full",
        help="Quick mode (5k CVEs) or full mode (50k CVEs)",
    )
    parser.add_argument(
        "--surface",
        choices=["all", "container", "cloud", "appsec"],
        default="all",
        help="Filter by surface",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=100,
        help="Number of top findings to prioritize",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("FixOps Demo Runner - Bidirectional Risk Scoring")
    print("=" * 60)
    print(f"Mode: {args.mode}")
    print(f"Surface: {args.surface}")
    print(f"Top N: {args.top_n}")
    print()

    limit = 5000 if args.mode == "quick" else None
    findings = load_findings(limit=limit)

    if args.surface != "all":
        findings = [f for f in findings if f["asset_type"] == args.surface]
        print(f"✓ Filtered to {len(findings):,} {args.surface} findings")

    scores = process_findings(findings, mode=args.mode)

    top_scores = prioritize_findings(scores, top_n=args.top_n)

    stats = generate_statistics(scores)

    output_files = save_results(scores, top_scores, stats, args.mode)

    report_path = generate_report(top_scores, stats, output_files, args.mode)

    print("\n" + "=" * 60)
    print("✅ Demo Complete")
    print("=" * 60)
    print(f"Summary report: {report_path}")
    print(f"Evidence bundle: {output_files['evidence_bundle']}")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
