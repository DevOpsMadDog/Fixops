#!/usr/bin/env bash
#
# Deterministic structural map of this codebase — tree-sitter, ZERO LLM calls.
#
# This is Understand-Anything's FREE layer. Its /understand skill dispatches an
# LLM subagent per batch and is expensive at our scale (5,829 Python files), but
# the two scripts underneath it are pure tree-sitter and cost nothing.
#
# Measured on this repo:
#   suite-core/core            947 files   2,366 fn   141,124 call edges   5.8s
#   suite-api/apps/api         813 files   8,276 fn    56,782 call edges
#   suite-ui/.../src           510 files   1,836 fn    20,108 call edges
#   suite-evidence-risk         75 files     171 fn     5,542 call edges
#
# This REPLACES graphify, which took 20 minutes and produced a false call graph:
# it collapsed every `.get()` in the repo into one node, making a three-line dict
# getter the most-connected symbol in 2.2M LOC. UA qualifies the receiver
# (`data.get`, `conn.execute`, `self._conn`), so the counts mean something.
#
#   ./scripts/ua-structure.sh [path ...]     default: the four suites above
#
set -uo pipefail
UA="${UA_PLUGIN:-$HOME/.understand-anything/repo/understand-anything-plugin}"
OUT="${UA_OUT:-.ua/intermediate}"
mkdir -p "$OUT"

if [[ ! -f "$UA/packages/core/dist/index.js" ]]; then
  echo "UA core not built. Run: cd $UA && pnpm install && pnpm --filter @understand-anything/core build" >&2
  exit 1
fi

targets=("$@")
[[ ${#targets[@]} -eq 0 ]] && targets=(suite-core/core suite-api/apps/api suite-evidence-risk suite-ui/aldeci-ui-new/src)

printf '%6s %8s %10s  %s\n' FILES FUNCS "CALL-EDGES" TARGET
for t in "${targets[@]}"; do
  [[ -d "$t" ]] || { echo "  skip (missing): $t"; continue; }
  n=$(echo "$t" | tr '/' '_')
  node "$UA/skills/understand/scan-project.mjs" "$(pwd)/$t" "$OUT/$n-scan.json" >/dev/null 2>&1
  python3 - "$t" "$OUT/$n-scan.json" "$OUT/$n-in.json" <<'PY'
import json, pathlib, sys
target, scan_path, out_path = sys.argv[1:4]
scan = json.load(open(scan_path))
json.dump({"projectRoot": str(pathlib.Path(target).resolve()),
           "batchFiles": [{"path": f["path"], "language": f["language"],
                           "sizeLines": int(f["sizeLines"]), "fileCategory": f["fileCategory"]}
                          for f in scan["files"]]}, open(out_path, "w"))
PY
  node "$UA/skills/understand/extract-structure.mjs" "$OUT/$n-in.json" "$OUT/$n-struct.json" >/dev/null 2>&1
  python3 - "$OUT/$n-struct.json" "$t" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["results"]
fn = sum(len(x.get("functions") or []) for x in d)
cg = sum(len(x.get("callGraph") or []) for x in d)
print(f"{len(d):6} {fn:8,} {cg:10,}  {sys.argv[2]}")
PY
done
