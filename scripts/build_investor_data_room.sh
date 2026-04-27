#!/usr/bin/env bash
# =============================================================================
# build_investor_data_room.sh
# ALdeci Series A — Investor Data Room Bundle Assembly
# =============================================================================
# Usage: bash scripts/build_investor_data_room.sh [DATE]
#   DATE defaults to 2026-04-26
# Output: dist/data_room_<DATE>/ + dist/aldeci_data_room_<DATE>.tar.gz
#         dist/aldeci_data_room_<DATE>.manifest.sha256
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DATE="${1:-2026-04-26}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist/data_room_$DATE"
TARBALL="$REPO_ROOT/dist/aldeci_data_room_$DATE.tar.gz"
MANIFEST="$REPO_ROOT/dist/aldeci_data_room_$DATE.manifest.sha256"

echo "======================================================================"
echo "  ALdeci Investor Data Room Builder"
echo "  Date   : $DATE"
echo "  Root   : $REPO_ROOT"
echo "  Output : $DIST_DIR"
echo "======================================================================"

# ---------------------------------------------------------------------------
# Helper: safe copy — skips if source does not exist, logs a warning
# ---------------------------------------------------------------------------
safe_cp() {
  local src="$1"
  local dst_dir="$2"
  if [[ -f "$src" ]]; then
    cp "$src" "$dst_dir/"
    echo "  [OK]  $src"
  else
    echo "  [SKIP] (not found) $src"
  fi
}

# ---------------------------------------------------------------------------
# Helper: safe copy entire directory tree
# ---------------------------------------------------------------------------
safe_cp_tree() {
  local src_dir="$1"
  local dst_dir="$2"
  if [[ -d "$src_dir" ]]; then
    cp -r "$src_dir/." "$dst_dir/"
    echo "  [OK]  $src_dir/ (tree)"
  else
    echo "  [SKIP] (dir not found) $src_dir"
  fi
}

# ---------------------------------------------------------------------------
# 0. Clean + create directory structure
# ---------------------------------------------------------------------------
echo ""
echo "--- Creating directory structure ---"
rm -rf "$DIST_DIR"
mkdir -p \
  "$DIST_DIR/01_executive_summary" \
  "$DIST_DIR/02_competitive_validation" \
  "$DIST_DIR/03_product_demo" \
  "$DIST_DIR/04_technical_architecture" \
  "$DIST_DIR/05_federal_scif" \
  "$DIST_DIR/06_traction_metrics" \
  "$DIST_DIR/07_team" \
  "$DIST_DIR/08_legal_ip"
echo "  Directory tree created."

# ---------------------------------------------------------------------------
# 01 — Executive Summary
# ---------------------------------------------------------------------------
echo ""
echo "--- 01_executive_summary ---"
safe_cp "$REPO_ROOT/docs/investor/INVESTOR_PACK_2026-04-26.md"         "$DIST_DIR/01_executive_summary"
safe_cp "$REPO_ROOT/docs/pitch/ONE_PAGER_2026-04-26.md"                "$DIST_DIR/01_executive_summary"
safe_cp "$REPO_ROOT/docs/investor/TRACTION_METRICS_2026-04-26.md"      "$DIST_DIR/01_executive_summary"
safe_cp "$REPO_ROOT/docs/pitch/ALDECI_PITCH_DECK_2026-04-26.md"        "$DIST_DIR/01_executive_summary"
safe_cp "$REPO_ROOT/docs/pitch/objection_handling_2026-04-26.md"       "$DIST_DIR/01_executive_summary"

# ---------------------------------------------------------------------------
# 02 — Competitive Validation
# ---------------------------------------------------------------------------
echo ""
echo "--- 02_competitive_validation ---"
safe_cp "$REPO_ROOT/docs/competitive_validation_2026-04-26.md"                        "$DIST_DIR/02_competitive_validation"
safe_cp "$REPO_ROOT/raw/competitive/gap-matrix-2026-04-26.md"                         "$DIST_DIR/02_competitive_validation"
safe_cp "$REPO_ROOT/raw/competitive/truecourse-vs-fixops-comparison.md"               "$DIST_DIR/02_competitive_validation"
safe_cp "$REPO_ROOT/raw/competitive/competitor-aspm.md"                               "$DIST_DIR/02_competitive_validation"
safe_cp "$REPO_ROOT/raw/competitive/competitor-cspm.md"                               "$DIST_DIR/02_competitive_validation"
safe_cp "$REPO_ROOT/raw/competitive/competitor-ctem.md"                               "$DIST_DIR/02_competitive_validation"
safe_cp "$REPO_ROOT/raw/competitive/competitor-emerging.md"                           "$DIST_DIR/02_competitive_validation"
safe_cp "$REPO_ROOT/raw/competitive/competitor-sonatype.md"                           "$DIST_DIR/02_competitive_validation"
# Battle cards sub-directory
mkdir -p "$DIST_DIR/02_competitive_validation/battle_cards"
for card in snyk wiz tenable apiiro aikido sonatype xm_cyber; do
  safe_cp "$REPO_ROOT/docs/sales/battle_cards/${card}.md" "$DIST_DIR/02_competitive_validation/battle_cards"
done

# ---------------------------------------------------------------------------
# 03 — Product Demo
# ---------------------------------------------------------------------------
echo ""
echo "--- 03_product_demo ---"
safe_cp "$REPO_ROOT/docs/sales/demo_script_30min.md"                   "$DIST_DIR/03_product_demo"
safe_cp "$REPO_ROOT/docs/sales/poc_template.md"                        "$DIST_DIR/03_product_demo"
safe_cp "$REPO_ROOT/docs/sales/customer_onboarding_playbook.md"        "$DIST_DIR/03_product_demo"
safe_cp "$REPO_ROOT/docs/sales/win_loss_analysis_template.md"          "$DIST_DIR/03_product_demo"
# Screenshots — copy if directory exists
if [[ -d "$REPO_ROOT/docs/ui-snapshots" ]]; then
  mkdir -p "$DIST_DIR/03_product_demo/ui-snapshots"
  safe_cp_tree "$REPO_ROOT/docs/ui-snapshots" "$DIST_DIR/03_product_demo/ui-snapshots"
else
  echo "  [SKIP] (dir not found) docs/ui-snapshots"
fi

# ---------------------------------------------------------------------------
# 04 — Technical Architecture
# ---------------------------------------------------------------------------
echo ""
echo "--- 04_technical_architecture ---"
safe_cp "$REPO_ROOT/docs/CTEM_PLUS_IDENTITY.md"                        "$DIST_DIR/04_technical_architecture"
safe_cp "$REPO_ROOT/docs/UX_CONSOLIDATION_PLAN_2026-04-26.md"          "$DIST_DIR/04_technical_architecture"
safe_cp "$REPO_ROOT/docs/LLM_TRAINING_ROADMAP_2026-04-26.md"           "$DIST_DIR/04_technical_architecture"
safe_cp "$REPO_ROOT/docs/self_learning_llm_scope_2026-04-26.md"        "$DIST_DIR/04_technical_architecture"
safe_cp "$REPO_ROOT/docs/ALDECI_REARCHITECTURE_v2.md"                  "$DIST_DIR/04_technical_architecture"

# ---------------------------------------------------------------------------
# 05 — Federal SCIF
# ---------------------------------------------------------------------------
echo ""
echo "--- 05_federal_scif ---"
safe_cp_tree "$REPO_ROOT/docs/scif" "$DIST_DIR/05_federal_scif"
safe_cp "$REPO_ROOT/docs/scif_readiness_2026-04-26.md"                 "$DIST_DIR/05_federal_scif"

# ---------------------------------------------------------------------------
# 06 — Traction Metrics
# ---------------------------------------------------------------------------
echo ""
echo "--- 06_traction_metrics ---"
safe_cp "$REPO_ROOT/docs/investor/TRACTION_METRICS_2026-04-26.md"      "$DIST_DIR/06_traction_metrics"
safe_cp "$REPO_ROOT/docs/investor/data_room_index.md"                  "$DIST_DIR/06_traction_metrics"
safe_cp "$REPO_ROOT/docs/multi_tenant_onboarding_results_2026-04-24.md" "$DIST_DIR/06_traction_metrics"
safe_cp "$REPO_ROOT/docs/persona_coverage_after_seed.md"               "$DIST_DIR/06_traction_metrics"
safe_cp "$REPO_ROOT/docs/ORG_WIDE_PERSONA_TRIAL_RUNBOOK.md"            "$DIST_DIR/06_traction_metrics"

# ---------------------------------------------------------------------------
# 07 — Team (placeholder)
# ---------------------------------------------------------------------------
echo ""
echo "--- 07_team (placeholder) ---"
cat > "$DIST_DIR/07_team/README.md" <<'PLACEHOLDER'
# Team

To be filled in by founder prior to sharing with investors.

Suggested sections:
- Founding team bios (LinkedIn URLs, prior companies, relevant exits)
- Key hires plan (first 5 roles post-Series A)
- Advisors and board observers
- Reference contacts (with permission)

> Note: Do not include personal contact details or SSNs in this document.
PLACEHOLDER
echo "  [OK]  07_team/README.md (placeholder)"

# ---------------------------------------------------------------------------
# 08 — Legal & IP (placeholder)
# ---------------------------------------------------------------------------
echo ""
echo "--- 08_legal_ip (placeholder) ---"
cat > "$DIST_DIR/08_legal_ip/README.md" <<'PLACEHOLDER'
# Legal & IP

Coming pre-close. Will include:

- Certificate of Incorporation / Articles of Association
- Cap table (as of signing date)
- IP assignment agreements (all founders + contractors)
- Key employment agreements (redacted)
- Open-source license audit summary
- Patent applications (if any) — titles only, no claims pre-filing
- NDAs on file with design partners (existence confirmed, contents confidential)

> Note: Actual legal documents are shared only under executed NDA via secure
> virtual data room (VDR). This placeholder will be replaced by a VDR access
> link during due diligence.
PLACEHOLDER
echo "  [OK]  08_legal_ip/README.md (placeholder)"

# ---------------------------------------------------------------------------
# Root README
# ---------------------------------------------------------------------------
echo ""
echo "--- Generating _README.md ---"
cat > "$DIST_DIR/_README.md" <<ROOTREADME
# ALdeci — Series A Investor Data Room
**Built:** $DATE
**Platform:** ALdeci CTEM+ (Continuous Threat Exposure Management Plus)
**Stage:** Series A
**Branch:** features/intermediate-stage

---

## How to Navigate This Data Room

Start with **01_executive_summary/INVESTOR_PACK_2026-04-26.md** — the master
narrative that synthesises every section below into a single investor document.
Then walk the folders in numeric order.

---

## Folder Structure

\`\`\`
data_room_$DATE/
├── 01_executive_summary/       Master pitch pack, one-pager, traction fact sheet
├── 02_competitive_validation/  149-cap scorecard, gap matrix, 7 competitor deep-dives,
│   └── battle_cards/           7 per-competitor win/loss battle cards
├── 03_product_demo/            30-min demo script, POC template, onboarding playbook
├── 04_technical_architecture/  CTEM+ identity, LLM roadmap, UX consolidation plan
├── 05_federal_scif/            SSP, POAM, NIST 800-53 matrix, crypto datasheet,
│                               STIG checklist, air-gap runbook, SCIF pilot bundle
├── 06_traction_metrics/        DPO pairs, commit velocity, NIST coverage, multi-tenant
│                               onboarding results, persona coverage map
├── 07_team/                    README — founder to complete pre-share
└── 08_legal_ip/                README — provided under NDA pre-close
\`\`\`

---

## Key Numbers (as of $DATE)

| Metric | Value |
|--------|-------|
| Beast Mode tests passing | 806 |
| Native scanners (built-in) | 8 |
| External scanner parsers | 25+ |
| Brain Pipeline steps | 12 |
| MPTE exploit-verification phases | 19 |
| Connectors (pull + bidirectional) | 20 |
| NIST SP 800-53 control coverage | ~95% |
| DPO preference pairs (live) | 703 |
| Competitive scorecard: WIN or MATCH | 83% (149 caps × 7 competitors) |

---

## Redaction Notice

This data room has been reviewed for the following before sharing:

- No API keys, secrets, or credentials
- No named customer data or PII
- No source-code paths beyond architecture references
- No unexecuted term sheets or cap-table numbers
- Federal sponsor names in target lists are directional, not contracted

See \`docs/investor/data_room_assembly_runbook.md\` for full redaction checklist.

---

*Generated by \`scripts/build_investor_data_room.sh\`. To rebuild: \`bash scripts/build_investor_data_room.sh $DATE\`*
ROOTREADME
echo "  [OK]  _README.md"

# ---------------------------------------------------------------------------
# SHA-256 Manifest
# ---------------------------------------------------------------------------
echo ""
echo "--- Generating SHA-256 manifest ---"
mkdir -p "$(dirname "$MANIFEST")"
# Use shasum on macOS, sha256sum on Linux
SHABIN="sha256sum"
command -v sha256sum &>/dev/null || SHABIN="shasum -a 256"

(
  cd "$DIST_DIR"
  find . -type f | sort | while read -r f; do
    $SHABIN "$f"
  done
) > "$MANIFEST"

FILE_COUNT=$(wc -l < "$MANIFEST" | tr -d ' ')
echo "  [OK]  Manifest written: $FILE_COUNT files hashed"
echo "        $MANIFEST"

# ---------------------------------------------------------------------------
# Tarball
# ---------------------------------------------------------------------------
echo ""
echo "--- Creating tarball ---"
(
  cd "$(dirname "$DIST_DIR")"
  tar -czf "$TARBALL" "$(basename "$DIST_DIR")"
)
TARBALL_SIZE=$(du -sh "$TARBALL" | cut -f1)
echo "  [OK]  $TARBALL ($TARBALL_SIZE)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  BUILD COMPLETE"
echo "  Files  : $FILE_COUNT"
echo "  Bundle : $TARBALL ($TARBALL_SIZE)"
echo "  Manifest: $MANIFEST"
echo ""
echo "  To share: upload the .tar.gz to a protected Dropbox/Drive link"
echo "  See docs/investor/data_room_assembly_runbook.md for sharing SOP"
echo "======================================================================"
