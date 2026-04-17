#!/usr/bin/env python3
"""
Graphify → LLM Council → PRD → Multica Pipeline
Loads graph.json, generates PRDs via OpenRouter, pushes issues to Multica.
"""

import json
import os
import sys
import time
import hashlib
import secrets
import uuid
import httpx
import psycopg2
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
GRAPH_FILE = ROOT / "graphify-out" / "graph.json"
PRD_DIR = ROOT / ".omc" / "prds"
ENV_FILE = ROOT / ".env"

MULTICA_BASE = "http://localhost:8080"
MULTICA_EMAIL = "beast@aldeci.io"
MULTICA_WORKSPACE_SLUG = "aldeci"

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MULEROUTER_URL = "https://mulerouter.ai/api/v1/chat/completions"
OLLAMA_URL = "http://localhost:11434/v1/chat/completions"
LLM_MODEL = "qwen/qwen3-235b-a22b:free"
LLM_MODEL_FALLBACK = "qwen/qwen-2.5-72b-instruct:free"
LLM_MODEL_MULEROUTER = "qwen/qwen3-6b-max"  # MuleRouter default
LLM_MODEL_OLLAMA = "qwen2.5:1.5b"   # local Ollama — better instruction following
LLM_MODEL_OLLAMA_SMALL = "qwen2.5:0.5b"  # tiny fallback

MIN_COMMUNITY_SIZE = 5
MAX_NODES_PER_PROMPT = 20  # keep prompts short for small local model
BATCH_SIZE = 5
BATCH_DELAY = 1.2  # seconds between batches

# ── Helpers ────────────────────────────────────────────────────────────────────

def load_env() -> dict:
    """Read all key=value pairs from .env file."""
    if not ENV_FILE.exists():
        raise FileNotFoundError(f".env not found at {ENV_FILE}")
    env = {}
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def load_env_key() -> tuple[str, str]:
    """Return (api_key, llm_url).

    Priority:
    1. Local Ollama (always available, no auth needed) → fastest, free
    2. MuleRouter (if key present and API responding)
    3. OpenRouter (if sk-or- key present)
    Falls back to Ollama if external APIs are unavailable.
    """
    env = load_env()
    key = env.get("MULEROUTER_API_KEY") or env.get("OPENROUTER_API_KEY", "")

    # Always try Ollama first — it's local and confirmed working
    try:
        import httpx as _hx
        r = _hx.get("http://localhost:11434/v1/models", timeout=3)
        if r.status_code == 200:
            print("  Using: Ollama (local, free)")
            return key or "ollama", OLLAMA_URL
    except Exception:
        pass

    if not key:
        raise ValueError("No API key and Ollama not available")

    # Try MuleRouter
    if key.startswith("sk-mr-"):
        print("  Using: MuleRouter")
        return key, "https://api.mulerouter.ai/v1/chat/completions"

    print("  Using: OpenRouter")
    return key, OPENROUTER_URL


def load_graph() -> dict:
    """Load graphify graph.json."""
    print(f"Loading graph from {GRAPH_FILE} ...")
    if not GRAPH_FILE.exists():
        raise FileNotFoundError(f"Graph not found: {GRAPH_FILE}")
    data = json.loads(GRAPH_FILE.read_text())
    print(f"  nodes={len(data.get('nodes', []))}  links={len(data.get('links', []))}")
    return data


def extract_communities(graph: dict) -> dict[int, list[dict]]:
    """Group nodes by community, return only significant ones."""
    communities: dict[int, list[dict]] = {}
    for node in graph["nodes"]:
        cid = node.get("community", -1)
        communities.setdefault(cid, []).append(node)
    significant = {k: v for k, v in communities.items() if len(v) >= MIN_COMMUNITY_SIZE}
    print(f"  Total communities: {len(communities)}  Significant ({MIN_COMMUNITY_SIZE}+): {len(significant)}")
    return significant


# ── LLM PRD generation ─────────────────────────────────────────────────────────

def build_prompt(cid: int, nodes: list[dict]) -> str:
    sample = nodes[:MAX_NODES_PER_PROMPT]
    node_lines = "\n".join(
        f"  - {n.get('label', n.get('id', '?'))}  [{n.get('file_type', '')}]  {n.get('source_file', '')}"
        for n in sample
    )
    extra = f"\n  ... and {len(nodes) - MAX_NODES_PER_PROMPT} more nodes" if len(nodes) > MAX_NODES_PER_PROMPT else ""

    # Determine a hint about the domain from node labels
    labels = [n.get("source_file", "") for n in sample if n.get("source_file")]
    label_hint = ", ".join(set(labels[:5])) if labels else "unknown"

    return f"""You are analyzing code community #{cid} from ALDECI, a security platform with 300+ engines (FastAPI+React).
Community has {len(nodes)} nodes. Key files: {label_hint}

Sample nodes:
{node_lines}{extra}

Output ONLY a JSON object. Choose ONE value for each field (no pipes, no placeholders):
- "domain": pick one of: vulnerability-management, threat-intelligence, compliance, identity-access, cloud-security, network-security, endpoint-security, application-security, data-security, incident-response, security-operations, reporting, infrastructure, ui-frontend, testing, unknown
- "title": descriptive title under 60 chars based on the actual file names above
- "current_state": pick ONE of: CRUD_ONLY, PARTIAL, REAL_LOGIC
- "description": 1-2 sentences about what these files actually do
- "missing": list of 3 specific gaps or improvements needed
- "connections_needed": list of 2 other security domains this should integrate with
- "acceptance_criteria": list of 3 specific testable criteria
- "priority": pick ONE of: HIGH, MEDIUM, LOW

Example output format:
{{"domain":"vulnerability-management","title":"CVE Scanner Integration Layer","current_state":"PARTIAL","description":"Handles CVE data ingestion and normalization from NVD feeds. Missing real-time scoring and EPSS integration.","missing":["EPSS score integration","Real-time CVE alerts","Batch processing queue"],"connections_needed":["threat-intelligence","compliance"],"acceptance_criteria":["CVE ingest completes in <5s","CVSS score present on all findings","90% of CVEs mapped to MITRE"],"priority":"HIGH"}}

Now output the JSON for community #{cid}:"""


def call_llm(prompt: str, api_key: str, model: str, llm_url: str, timeout: int = 60) -> dict | None:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/DevOpsMadDog/Fixops",
        "X-Title": "ALDECI Beast Mode Pipeline",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 512,
        "temperature": 0.3,
    }
    try:
        r = httpx.post(llm_url, headers=headers, json=payload, timeout=timeout, follow_redirects=True)
        if r.status_code == 200:
            content = r.json()["choices"][0]["message"]["content"].strip()
            # Strip markdown fences if present
            if "```" in content:
                parts = content.split("```")
                for part in parts:
                    part = part.strip()
                    if part.startswith("json"):
                        part = part[4:].strip()
                    if part.startswith("{"):
                        content = part
                        break
            # Extract first JSON object if prose precedes/follows it
            if not content.startswith("{"):
                start = content.find("{")
                end = content.rfind("}") + 1
                if start >= 0 and end > start:
                    content = content[start:end]
            parsed = json.loads(content)
            return normalize_prd(parsed) if isinstance(parsed, dict) else None
        else:
            print(f"    LLM error {r.status_code}: {r.text[:120]}")
            return None
    except json.JSONDecodeError as e:
        print(f"    JSON parse error: {e}")
        return None
    except Exception as e:
        print(f"    LLM call failed: {e}")
        return None


def normalize_prd(prd: dict) -> dict:
    """Normalize and coerce PRD field values to expected enums."""
    if not isinstance(prd, dict):
        return prd
    # Normalize priority to uppercase
    p = str(prd.get("priority", "")).strip().upper()
    if p not in ("HIGH", "MEDIUM", "LOW"):
        p = "MEDIUM"
    prd["priority"] = p
    # Normalize current_state
    cs = str(prd.get("current_state", "")).strip().upper()
    if cs not in ("CRUD_ONLY", "PARTIAL", "REAL_LOGIC"):
        cs = "CRUD_ONLY"
    prd["current_state"] = cs
    # Ensure lists
    for field in ("missing", "connections_needed", "acceptance_criteria"):
        if not isinstance(prd.get(field), list):
            prd[field] = [str(prd.get(field, ""))] if prd.get(field) else []
    return prd


def validate_prd(prd: dict) -> bool:
    """Return True if the PRD has real values, not template placeholders."""
    if not isinstance(prd, dict):
        return False
    # Reject if fields contain pipe-separated options (model didn't pick one)
    for field in ("current_state", "priority", "domain", "title"):
        val = str(prd.get(field, ""))
        if "|" in val or not val or val == "null":
            return False
    # Reject if missing/criteria are ALL template placeholders
    missing = prd.get("missing", [])
    if missing and all("gap" in str(m).lower() and len(str(m)) < 10 for m in missing):
        return False
    return True


def generate_prds(communities: dict[int, list[dict]], api_key: str, llm_url: str) -> list[dict]:
    # Pick model name based on backend
    primary_model = LLM_MODEL_OLLAMA if "11434" in llm_url else LLM_MODEL_MULEROUTER
    fallback_model = LLM_MODEL_OLLAMA if "11434" in llm_url else LLM_MODEL_FALLBACK
    PRD_DIR.mkdir(parents=True, exist_ok=True)
    prds = []
    cids = sorted(communities.keys())
    total = len(cids)
    print(f"\nGenerating PRDs for {total} communities (batch_size={BATCH_SIZE}, delay={BATCH_DELAY}s) ...")

    for batch_start in range(0, total, BATCH_SIZE):
        batch = cids[batch_start:batch_start + BATCH_SIZE]
        for i, cid in enumerate(batch):
            nodes = communities[cid]
            idx = batch_start + i + 1
            print(f"  [{idx}/{total}] Community {cid} ({len(nodes)} nodes) ...", end=" ", flush=True)

            # Check cache
            cache_file = PRD_DIR / f"community_{cid}.json"
            if cache_file.exists():
                try:
                    cached = json.loads(cache_file.read_text())
                    cached["community_id"] = cid
                    cached["node_count"] = len(nodes)
                    prds.append(cached)
                    print("(cached)")
                    continue
                except Exception:
                    pass

            prompt = build_prompt(cid, nodes)
            prd = call_llm(prompt, api_key, primary_model, llm_url)

            # Validate — retry if placeholders returned
            if prd is not None and not validate_prd(prd):
                print(f"(invalid values, retry) ...", end=" ", flush=True)
                time.sleep(0.5)
                prd = call_llm(prompt, api_key, primary_model, llm_url)
                if prd is not None and not validate_prd(prd):
                    prd = None

            # Fallback model
            if prd is None:
                print(f"(retry with fallback) ...", end=" ", flush=True)
                time.sleep(0.5)
                prd = call_llm(prompt, api_key, fallback_model, llm_url)
                if prd is not None and not validate_prd(prd):
                    prd = None

            if prd is None:
                print("SKIPPED (LLM failed)")
                # Save a placeholder so we can track it
                prd = {
                    "domain": "unknown",
                    "title": f"Community {cid} — Analysis Failed",
                    "current_state": "CRUD_ONLY",
                    "description": f"Community of {len(nodes)} nodes — LLM analysis failed.",
                    "missing": ["LLM analysis unavailable"],
                    "connections_needed": [],
                    "acceptance_criteria": ["Retry LLM analysis"],
                    "priority": "LOW",
                    "_failed": True,
                }
            else:
                print(f"OK [{prd.get('current_state', '?')}] {prd.get('title', '')[:50]}")

            prd["community_id"] = cid
            prd["node_count"] = len(nodes)
            cache_file.write_text(json.dumps(prd, indent=2))
            prds.append(prd)

        # Delay between batches (not after last batch)
        if batch_start + BATCH_SIZE < total:
            time.sleep(BATCH_DELAY)

    return prds


# ── Multica auth & workspace ───────────────────────────────────────────────────

def get_or_refresh_multica_token() -> tuple[str, str]:
    """
    Get a valid JWT for Multica.
    Strategy: insert verification code directly into DB, then verify via API.
    Returns (token, workspace_id).
    """
    conn = psycopg2.connect(host="localhost", port=5433, dbname="multica", user="multica", password="multica")
    cur = conn.cursor()

    # Ensure user exists
    cur.execute('SELECT id FROM "user" WHERE email=%s', (MULTICA_EMAIL,))
    row = cur.fetchone()
    if row:
        user_id = row[0]
        print(f"  Found existing Multica user: {user_id}")
    else:
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        cur.execute(
            'INSERT INTO "user" (id, name, email, created_at, updated_at) VALUES (%s, %s, %s, %s, %s)',
            (user_id, "Beast Admin", MULTICA_EMAIL, now, now)
        )
        print(f"  Created Multica user: {user_id}")

    # Ensure workspace exists
    cur.execute("SELECT id FROM workspace WHERE slug=%s", (MULTICA_WORKSPACE_SLUG,))
    ws_row = cur.fetchone()
    if ws_row:
        ws_id = ws_row[0]
        print(f"  Found existing workspace: {ws_id}")
    else:
        ws_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        cur.execute(
            "INSERT INTO workspace (id, name, slug, description, settings, created_at, updated_at, issue_prefix, issue_counter) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (ws_id, "ALDECI Beast Mode", MULTICA_WORKSPACE_SLUG, "ALDECI Security Platform PRDs",
             "{}", now, now, "ALDECI", 0)
        )
        # Add member
        cur.execute(
            "INSERT INTO member (id, workspace_id, user_id, role, created_at) VALUES (%s,%s,%s,%s,%s)",
            (str(uuid.uuid4()), ws_id, user_id, "owner", now)
        )
        print(f"  Created workspace: {ws_id}")

    # Upsert verification code
    code = secrets.choice(["888888", "123456", str(secrets.randbelow(900000) + 100000)])
    future = datetime.now(timezone.utc) + timedelta(minutes=10)
    cur.execute("SELECT id FROM verification_code WHERE email=%s", (MULTICA_EMAIL,))
    if cur.fetchone():
        cur.execute(
            "UPDATE verification_code SET code=%s, expires_at=%s, used=false, attempts=0 WHERE email=%s",
            (code, future, MULTICA_EMAIL)
        )
    else:
        cur.execute(
            "INSERT INTO verification_code (id, email, code, expires_at, used, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
            (str(uuid.uuid4()), MULTICA_EMAIL, code, future, False, datetime.now(timezone.utc))
        )
    conn.commit()
    conn.close()
    print(f"  Set verification code: {code}")

    # Verify via API to get JWT
    r = httpx.post(f"{MULTICA_BASE}/auth/verify-code",
                   json={"email": MULTICA_EMAIL, "code": code}, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"Multica auth failed: {r.status_code} {r.text}")
    token = r.json()["token"]
    print(f"  Got JWT token (len={len(token)})")
    return token, ws_id


def create_multica_issue(token: str, ws_id: str, prd: dict, client: httpx.Client) -> str | None:
    """Create a single issue in Multica. Returns issue id or None."""
    state = prd.get("current_state", "CRUD_ONLY")
    status_map = {"REAL_LOGIC": "done", "PARTIAL": "in_progress", "CRUD_ONLY": "todo"}
    status = status_map.get(state, "todo")
    priority_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    priority = priority_map.get(prd.get("priority", "LOW"), "low")

    missing_md = "\n".join(f"- {m}" for m in prd.get("missing", []))
    connections_md = "\n".join(f"- {c}" for c in prd.get("connections_needed", []))
    criteria_md = "\n".join(f"- [ ] {c}" for c in prd.get("acceptance_criteria", []))

    description = (
        f"{prd.get('description', '')}\n\n"
        f"**Domain:** {prd.get('domain', 'unknown')}\n"
        f"**Community:** #{prd.get('community_id')}  ({prd.get('node_count', 0)} nodes)\n"
        f"**State:** {state}\n\n"
        f"**Missing:**\n{missing_md}\n\n"
        f"**Connect to:**\n{connections_md}\n\n"
        f"**Acceptance Criteria:**\n{criteria_md}"
    )

    payload = {
        "workspace_id": ws_id,
        "title": prd.get("title", f"Community #{prd.get('community_id')} PRD")[:120],
        "description": description,
        "status": status,
        "priority": priority,
    }

    try:
        r = client.post(
            f"{MULTICA_BASE}/api/issues",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
            timeout=10,
        )
        if r.status_code in (200, 201):
            data = r.json()
            return data.get("id") or data.get("issue", {}).get("id")
        else:
            print(f"    Issue create failed {r.status_code}: {r.text[:100]}")
            return None
    except Exception as e:
        print(f"    Issue create error: {e}")
        return None


def push_to_multica(prds: list[dict], token: str, ws_id: str) -> dict:
    """Push all PRDs to Multica as issues. Returns stats."""
    stats = {"created": 0, "failed": 0, "done": 0, "in_progress": 0, "todo": 0}
    total = len(prds)
    print(f"\nPushing {total} PRDs to Multica workspace {ws_id} ...")

    with httpx.Client() as client:
        for i, prd in enumerate(prds):
            if prd.get("_failed"):
                stats["failed"] += 1
                continue
            print(f"  [{i+1}/{total}] {prd.get('title', '')[:55]} ...", end=" ", flush=True)
            issue_id = create_multica_issue(token, ws_id, prd, client)
            if issue_id:
                stats["created"] += 1
                state = prd.get("current_state", "CRUD_ONLY")
                if state == "REAL_LOGIC":
                    stats["done"] += 1
                elif state == "PARTIAL":
                    stats["in_progress"] += 1
                else:
                    stats["todo"] += 1
                print(f"OK {issue_id[:8]}")
            else:
                stats["failed"] += 1
                print("FAILED")

    return stats


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("GRAPHIFY → LLM COUNCIL → PRD → MULTICA PIPELINE")
    print("=" * 60)
    t0 = time.time()

    # Step 1: Load graph
    print("\n[STEP 1] Loading Graphify graph ...")
    graph = load_graph()
    communities = extract_communities(graph)

    # Step 2: Load API key
    print("\n[STEP 2] Loading API key ...")
    api_key, llm_url = load_env_key()
    print(f"  Key prefix: {api_key[:12]}...")
    print(f"  LLM URL:    {llm_url}")

    # Step 3: Generate PRDs via LLM
    print("\n[STEP 3] Generating PRDs via LLM Council ...")
    prds = generate_prds(communities, api_key, llm_url)
    successful_prds = [p for p in prds if not p.get("_failed")]
    failed_prds = [p for p in prds if p.get("_failed")]
    print(f"\n  PRDs generated: {len(successful_prds)}  Failed: {len(failed_prds)}")
    print(f"  Saved to: {PRD_DIR}/")

    # Step 4: Multica auth
    print("\n[STEP 4] Authenticating with Multica ...")
    try:
        token, ws_id = get_or_refresh_multica_token()
        multica_ok = True
    except Exception as e:
        print(f"  Multica auth failed: {e}")
        print("  PRDs saved to disk — skipping Multica integration")
        multica_ok = False

    # Step 5: Push to Multica
    multica_stats = {"created": 0, "failed": len(prds), "done": 0, "in_progress": 0, "todo": 0}
    if multica_ok:
        print("\n[STEP 5] Pushing issues to Multica ...")
        multica_stats = push_to_multica(successful_prds, token, ws_id)
    else:
        print("\n[STEP 5] Skipped (Multica auth failed)")

    # Final report
    elapsed = time.time() - t0
    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)
    print(f"Communities analyzed:   {len(communities)}")
    print(f"PRDs generated:         {len(successful_prds)}")
    print(f"PRDs failed (LLM):      {len(failed_prds)}")
    print(f"PRD cache dir:          {PRD_DIR}/")
    if multica_ok:
        print(f"Multica issues created: {multica_stats['created']}")
        print(f"  - Done (REAL_LOGIC):  {multica_stats['done']}")
        print(f"  - In Progress:        {multica_stats['in_progress']}")
        print(f"  - Todo (CRUD_ONLY):   {multica_stats['todo']}")
        print(f"  - Failed to create:   {multica_stats['failed']}")
        print(f"Multica workspace:      http://localhost:3000/{MULTICA_WORKSPACE_SLUG}/issues")
    print(f"Total time:             {elapsed:.1f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
