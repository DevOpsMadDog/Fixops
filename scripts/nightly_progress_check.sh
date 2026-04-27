#!/usr/bin/env bash
# =============================================================================
# nightly_progress_check.sh — DPO pair growth tracker
#
# USAGE:
#   bash scripts/nightly_progress_check.sh
#   bash scripts/nightly_progress_check.sh --json       # machine-readable
#   bash scripts/nightly_progress_check.sh --slack-md   # Slack markdown
#
# OUTPUT: Markdown report suitable for posting to Slack / Discord / email.
#         Includes: current pair count, yesterday delta, ETA to 10 K,
#                   last log status, and a mini ASCII progress bar.
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${REPO_ROOT}/data"
CRON_LOG_DIR="${DATA_DIR}/cron"
TRAIN_JSONL="${DATA_DIR}/distill_train.jsonl"
MANIFEST="${DATA_DIR}/distill_dataset_manifest.json"

THRESHOLD=10000
MODE="${1:-}"  # --json | --slack-md | (default markdown)

# ---------------------------------------------------------------------------
# Current pair count
# ---------------------------------------------------------------------------
current_pairs=0
if [[ -f "${TRAIN_JSONL}" ]]; then
    current_pairs=$(wc -l < "${TRAIN_JSONL}" | tr -d ' ')
fi

# ---------------------------------------------------------------------------
# Pull manifest stats if available
# ---------------------------------------------------------------------------
manifest_pairs=0
manifest_ts=""
if command -v python3 &>/dev/null && [[ -f "${MANIFEST}" ]]; then
    read -r manifest_pairs manifest_ts < <(python3 - <<'EOF'
import json, sys
try:
    d = json.load(open(sys.argv[1] if len(sys.argv)>1 else
                       "/Users/devops.ai/fixops/Fixops/data/distill_dataset_manifest.json"))
    print(d["stats"].get("pairs_kept", 0), d.get("generated_at", "unknown"))
except Exception as e:
    print(0, "unknown")
EOF
    ) || true
fi

# Prefer manifest value (curator is authoritative)
if [[ "${manifest_pairs}" -gt 0 ]]; then
    current_pairs="${manifest_pairs}"
fi

# ---------------------------------------------------------------------------
# Yesterday's log — extract delta from header
# ---------------------------------------------------------------------------
yesterday=$(date -v-1d '+%F' 2>/dev/null || date -d 'yesterday' '+%F' 2>/dev/null || echo "")
yesterday_log="${CRON_LOG_DIR}/nightly_${yesterday}.log"
yesterday_status="NO_LOG"
yesterday_delta=0

if [[ -f "${yesterday_log}" ]]; then
    header=$(head -1 "${yesterday_log}")
    if [[ "${header}" == OK* ]]; then
        yesterday_status="OK"
        # Extract delta=+NNN from header
        if [[ "${header}" =~ delta=\+([0-9]+) ]]; then
            yesterday_delta="${BASH_REMATCH[1]}"
        fi
    elif [[ "${header}" == FAILED* ]]; then
        yesterday_status="FAILED"
        yesterday_status_detail=$(echo "${header}" | sed 's/FAILED [^ ]* — //')
    elif [[ "${header}" == RUNNING* ]]; then
        yesterday_status="STILL_RUNNING_OR_CRASHED"
    fi
fi

# ---------------------------------------------------------------------------
# Today's log status
# ---------------------------------------------------------------------------
today=$(date '+%F')
today_log="${CRON_LOG_DIR}/nightly_${today}.log"
today_status="NOT_YET_RUN"
if [[ -f "${today_log}" ]]; then
    header=$(head -1 "${today_log}")
    if [[ "${header}" == OK* ]]; then
        today_status="OK"
    elif [[ "${header}" == FAILED* ]]; then
        today_status="FAILED"
    elif [[ "${header}" == RUNNING* ]]; then
        today_status="IN_PROGRESS"
    fi
fi

# ---------------------------------------------------------------------------
# ETA calculation
# ---------------------------------------------------------------------------
remaining=$(( THRESHOLD - current_pairs ))
eta_nights="N/A"
eta_date="N/A"
if [[ "${yesterday_delta}" -gt 0 ]]; then
    eta_nights=$(( (remaining + yesterday_delta - 1) / yesterday_delta ))
    if command -v python3 &>/dev/null; then
        eta_date=$(python3 -c "
from datetime import date, timedelta
print((date.today() + timedelta(days=${eta_nights})).isoformat())
" 2>/dev/null || echo "N/A")
    fi
fi

# ---------------------------------------------------------------------------
# Progress bar (50 chars wide)
# ---------------------------------------------------------------------------
pct=$(( current_pairs * 100 / THRESHOLD ))
filled=$(( current_pairs * 50 / THRESHOLD ))
empty=$(( 50 - filled ))
bar=""
for (( i=0; i<filled; i++ )); do bar="${bar}#"; done
for (( i=0; i<empty;  i++ )); do bar="${bar}-"; done

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if [[ "${MODE}" == "--json" ]]; then
    python3 - <<EOF
import json
print(json.dumps({
    "current_pairs": ${current_pairs},
    "threshold": ${THRESHOLD},
    "remaining": ${remaining},
    "pct_complete": ${pct},
    "yesterday_delta": ${yesterday_delta},
    "eta_nights": "${eta_nights}",
    "eta_date": "${eta_date}",
    "yesterday_status": "${yesterday_status}",
    "today_status": "${today_status}",
    "manifest_ts": "${manifest_ts}"
}, indent=2))
EOF
    exit 0
fi

# Markdown / Slack-md output (identical — Slack renders standard markdown)
cat <<REPORT
## LLM Phase 1 DPO Pair Growth — $(date '+%Y-%m-%d')

| Metric | Value |
|--------|-------|
| **Current pairs** | ${current_pairs} / ${THRESHOLD} (${pct}%) |
| **Remaining to 10 K** | ${remaining} |
| **Yesterday's delta** | +${yesterday_delta} pairs |
| **ETA (nights)** | ${eta_nights} nights |
| **ETA (date)** | ${eta_date} |
| **Last night status** | ${yesterday_status} |
| **Tonight status** | ${today_status} |
| **Manifest timestamp** | ${manifest_ts} |

\`\`\`
Progress: [${bar}] ${pct}%
          0                   5K                  10K
\`\`\`

### Log files
- Yesterday : \`${yesterday_log}\`
- Today     : \`${today_log}\`

$(if [[ "${yesterday_status}" == "FAILED" ]]; then
    echo "> **ACTION REQUIRED**: Last night's scan FAILED."
    echo "> Check: \`head -5 ${yesterday_log}\`"
elif [[ "${eta_nights}" != "N/A" && "${eta_nights}" -le 1 ]]; then
    echo "> **Phase 2 GA threshold within 1 night — prepare distillation pipeline.**"
fi)
REPORT
