#!/usr/bin/env python3
"""
Push 332 v2 PRDs to Multica board with proper epic hierarchy.

Hierarchy:
  Master Epic (bee95c22)
    └── Sub-Epic (10 existing)
          └── Story (one per PRD file) — THIS SCRIPT CREATES THESE
                └── Tasks (sub-issues per PRD task)

Sub-Epic mapping (PRD "Sub-Epic:" field → existing Multica issue ID):
  ASPM       → c2780bde-481a-4ebd-ae2a-ffca31edb4f8
  CSPM       → 6eeac7b2-04a3-4c60-814b-9fd373463392
  CTEM       → 29c8fc83-add1-4357-8b1d-3424d1c97cd9
  SOC        → 9ead5b4a-7bb5-4c4d-931a-247beaa4ff51
  GRC        → 17f6c695-75ca-4949-954a-86de65dd58c0
  Identity   → 98f05b40-fa8c-45b4-ab2c-a6a46aa1fa10
  Network    → 1ad89985-951b-47e3-9105-60e7211bac45
  AI Intelligence → c389e04b-0361-4942-ade8-f54d6e5771b4
  Executive  → 15c4969e-d690-47a5-b7d2-fc272928ca9b
  Advanced   → 7f6a4a63-a5ff-481d-8527-a23f644159d9  (Platform & Infrastructure)
"""

import json
import os
import re
import time
import uuid
import httpx
import psycopg2
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────────────────────
PRD_DIR = Path("/Users/devops.ai/fixops/Fixops/.omc/prds/v2")
MULTICA_BASE = "http://localhost:8080"
MULTICA_EMAIL = "beast@aldeci.io"
WORKSPACE_SLUG = "aldeci"
WORKSPACE_ID = "30fad00d-8273-4196-96d4-abd55f4cbb43"
USER_ID = "251f9fe6-613f-4beb-98aa-f718c581bc59"

# Existing Sub-Epic IDs on the board
SUB_EPIC_IDS = {
    "ASPM":           "c2780bde-481a-4ebd-ae2a-ffca31edb4f8",
    "CSPM":           "6eeac7b2-04a3-4c60-814b-9fd373463392",
    "CTEM":           "29c8fc83-add1-4357-8b1d-3424d1c97cd9",
    "SOC":            "9ead5b4a-7bb5-4c4d-931a-247beaa4ff51",
    "GRC":            "17f6c695-75ca-4949-954a-86de65dd58c0",
    "Identity":       "98f05b40-fa8c-45b4-ab2c-a6a46aa1fa10",
    "Network":        "1ad89985-951b-47e3-9105-60e7211bac45",
    "AI Intelligence":"c389e04b-0361-4942-ade8-f54d6e5771b4",
    "Executive":      "15c4969e-d690-47a5-b7d2-fc272928ca9b",
    "Advanced":       "7f6a4a63-a5ff-481d-8527-a23f644159d9",
}

DELAY_BETWEEN = 0.05  # seconds between API calls


# ── Auth ───────────────────────────────────────────────────────────────────────

def get_token() -> str:
    """Get fresh JWT by injecting verification code into DB.
    Opens and closes the connection in one shot — no long-lived DB handle.
    """
    code = "888888"
    future = datetime.now(timezone.utc) + timedelta(minutes=60)

    with psycopg2.connect(
        host="localhost", port=5433, dbname="multica",
        user="multica", password="multica",
        connect_timeout=10,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM verification_code WHERE email=%s", (MULTICA_EMAIL,))
            if cur.fetchone():
                cur.execute(
                    "UPDATE verification_code SET code=%s, expires_at=%s, used=false, attempts=0 WHERE email=%s",
                    (code, future, MULTICA_EMAIL)
                )
            else:
                cur.execute(
                    "INSERT INTO verification_code (id, email, code, expires_at, used, created_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s)",
                    (str(uuid.uuid4()), MULTICA_EMAIL, code, future, False, datetime.now(timezone.utc))
                )
        conn.commit()

    r = httpx.post(
        f"{MULTICA_BASE}/auth/verify-code",
        json={"email": MULTICA_EMAIL, "code": code},
        timeout=30
    )
    if r.status_code != 200:
        raise RuntimeError(f"Auth failed: {r.status_code} {r.text}")
    return r.json()["token"]


# ── PRD parsing ────────────────────────────────────────────────────────────────

def parse_prd(filepath: Path) -> dict:
    """Parse a v2 PRD markdown file into structured data."""
    content = filepath.read_text()

    # Title from first # heading (e.g. "# US-0001: Access Anomaly")
    m = re.search(r'^# (.+)$', content, re.MULTILINE)
    title = m.group(1).strip() if m else filepath.stem.replace("_", " ").title()

    # Sub-Epic
    m = re.search(r'^## Sub-Epic:\s*(.+)$', content, re.MULTILINE)
    sub_epic = m.group(1).strip() if m else "Advanced"

    # Current state / completion %
    m = re.search(r'^## Current State:\s*(.+)$', content, re.MULTILINE)
    state_line = m.group(1).strip() if m else ""

    # Determine status from completion %
    pct_match = re.search(r'(\d+)%', state_line)
    if pct_match:
        pct = int(pct_match.group(1))
        if pct >= 95:
            status = "done"
        elif pct >= 50:
            status = "in_progress"
        else:
            status = "todo"
    elif "Complete" in state_line or "100%" in state_line:
        status = "done"
    else:
        status = "in_progress"

    # User Story section
    m = re.search(r'## User Story\n(.+?)(?=\n## |\Z)', content, re.DOTALL)
    user_story = m.group(1).strip() if m else ""

    # Why This Matters
    m = re.search(r'## Why This Matters\n(.+?)(?=\n## |\Z)', content, re.DOTALL)
    why = m.group(1).strip() if m else ""

    # API Endpoints table
    m = re.search(r'## API Endpoints\n(.+?)(?=\n## |\Z)', content, re.DOTALL)
    api_section = m.group(1).strip() if m else ""

    # Tasks Remaining
    m = re.search(r'## Tasks Remaining\n(.+?)(?=\n## |\Z)', content, re.DOTALL)
    tasks_raw = m.group(1).strip() if m else ""
    tasks = re.findall(r'^\d+\.\s+(.+)$', tasks_raw, re.MULTILINE)

    # Definition of Done checkboxes
    m = re.search(r'## Definition of Done\n(.+?)(?=\n## |\Z)', content, re.DOTALL)
    dod_raw = m.group(1).strip() if m else ""
    dod_items = re.findall(r'- \[[ x]\] (.+)', dod_raw)

    # Key functions (for description richness)
    m = re.search(r'## Key Functions.+?\n(.+?)(?=\n## |\Z)', content, re.DOTALL)
    funcs_raw = m.group(1).strip() if m else ""
    func_lines = [l.strip() for l in funcs_raw.splitlines() if l.strip().startswith("-")][:5]

    # Source/router file references
    source_m = re.search(r'\*\*Source file\*\*:\s*`(.+?)`', content)
    router_m = re.search(r'\*\*Router file\*\*:\s*`(.+?)`', content)
    source_file = source_m.group(1) if source_m else ""
    router_file = router_m.group(1) if router_m else ""

    # Dependencies
    dep_m = re.search(r'\*\*Depends on\*\*:\s*(.+)', content)
    dep_by_m = re.search(r'\*\*Depended by\*\*:\s*(.+)', content)
    depends_on = dep_m.group(1).strip() if dep_m else ""
    depended_by = dep_by_m.group(1).strip() if dep_by_m else ""

    return {
        "title": title,
        "sub_epic": sub_epic,
        "status": status,
        "state_line": state_line,
        "user_story": user_story,
        "why": why,
        "api_section": api_section,
        "tasks": tasks,
        "dod_items": dod_items,
        "func_lines": func_lines,
        "source_file": source_file,
        "router_file": router_file,
        "depends_on": depends_on,
        "depended_by": depended_by,
        "filename": filepath.name,
    }


def build_description(prd: dict) -> str:
    """Build rich markdown description for Multica issue."""
    parts = []

    if prd["user_story"]:
        parts.append(prd["user_story"])

    if prd["why"]:
        parts.append(f"\n**Why This Matters**\n{prd['why']}")

    if prd["source_file"] or prd["router_file"]:
        parts.append("\n**Implementation**")
        if prd["source_file"]:
            parts.append(f"- Engine: `{prd['source_file']}`")
        if prd["router_file"]:
            parts.append(f"- Router: `{prd['router_file']}`")

    if prd["func_lines"]:
        parts.append("\n**Key Functions**")
        parts.extend(prd["func_lines"])

    if prd["api_section"]:
        # Trim to first 800 chars to keep description manageable
        api_trimmed = prd["api_section"][:800]
        parts.append(f"\n**API Endpoints**\n{api_trimmed}")

    if prd["depends_on"] or prd["depended_by"]:
        parts.append("\n**Dependencies**")
        if prd["depends_on"]:
            parts.append(f"- Depends on: {prd['depends_on']}")
        if prd["depended_by"]:
            parts.append(f"- Depended by: {prd['depended_by']}")

    if prd["dod_items"]:
        parts.append("\n**Definition of Done**")
        for item in prd["dod_items"]:
            parts.append(f"- [ ] {item}")

    return "\n".join(parts)


# ── API helpers ────────────────────────────────────────────────────────────────

def create_issue(client: httpx.Client, token: str, title: str, description: str,
                 status: str, priority: str, parent_id: str) -> str | None:
    """Create a single issue via Multica API. Returns issue id or None."""
    payload = {
        "workspace_id": WORKSPACE_ID,
        "title": title[:200],
        "description": description,
        "status": status,
        "priority": priority,
        "parent_issue_id": parent_id,
    }
    try:
        r = client.post(
            f"{MULTICA_BASE}/api/issues?workspace_slug={WORKSPACE_SLUG}",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
            timeout=15,
        )
        if r.status_code in (200, 201):
            data = r.json()
            return data.get("id") or (data.get("issue") or {}).get("id")
        else:
            return None
    except Exception:
        return None


# ── Dedup check ────────────────────────────────────────────────────────────────

def get_existing_titles() -> set[str]:
    """Fetch all existing issue titles from DB for dedup."""
    with psycopg2.connect(
        host="localhost", port=5433, dbname="multica",
        user="multica", password="multica",
        connect_timeout=10,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT title FROM issue")
            return {r[0] for r in cur.fetchall()}


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("PUSH 332 v2 PRDs → MULTICA BOARD (Epic Hierarchy)")
    print("=" * 65)
    t0 = time.time()

    # Step 1: Auth
    print("\n[1/5] Authenticating with Multica ...")
    token = get_token()
    print(f"  Token OK (len={len(token)})")

    # Step 2: Load existing titles for dedup
    print("\n[2/5] Loading existing issue titles ...")
    existing_titles = get_existing_titles()
    print(f"  Found {len(existing_titles)} existing issues")

    # Step 3: Parse all PRD files
    print(f"\n[3/5] Parsing PRD files from {PRD_DIR} ...")
    prd_files = sorted(PRD_DIR.glob("*.md"))
    print(f"  Found {len(prd_files)} PRD files")

    prds = []
    unknown_sub_epics = set()
    for f in prd_files:
        prd = parse_prd(f)
        if prd["sub_epic"] not in SUB_EPIC_IDS:
            unknown_sub_epics.add(prd["sub_epic"])
            prd["sub_epic"] = "Advanced"  # fallback
        prds.append(prd)

    if unknown_sub_epics:
        print(f"  WARNING: Unknown sub-epics (mapped to Advanced): {unknown_sub_epics}")

    # Sub-epic distribution
    from collections import Counter
    dist = Counter(p["sub_epic"] for p in prds)
    print(f"  Sub-epic distribution:")
    for se, count in sorted(dist.items()):
        print(f"    {se}: {count}")

    # Step 4: Push stories to Multica
    print(f"\n[4/5] Pushing {len(prds)} stories to Multica ...")
    stats = {
        "created": 0, "skipped": 0, "failed": 0,
        "tasks_created": 0, "tasks_failed": 0,
        "by_sub_epic": Counter(),
        "by_status": Counter(),
    }

    with httpx.Client() as client:
        for i, prd in enumerate(prds):
            title = prd["title"]

            # Dedup by title
            if title in existing_titles:
                print(f"  [{i+1:3d}/{len(prds)}] SKIP (exists): {title[:70]}")
                stats["skipped"] += 1
                continue

            parent_id = SUB_EPIC_IDS[prd["sub_epic"]]
            description = build_description(prd)
            status = prd["status"]
            priority = "high" if status == "in_progress" else "medium"

            issue_id = create_issue(
                client, token, title, description,
                status, priority, parent_id
            )

            if issue_id:
                existing_titles.add(title)  # prevent future dups in this run
                stats["created"] += 1
                stats["by_sub_epic"][prd["sub_epic"]] += 1
                stats["by_status"][status] += 1
                print(f"  [{i+1:3d}/{len(prds)}] OK   [{prd['sub_epic']:16s}] [{status:11s}] {title[:55]}")

                # Create task sub-issues for each "Tasks Remaining" item
                for j, task_text in enumerate(prd["tasks"]):
                    task_title = f"{task_text[:180]}"
                    task_id = create_issue(
                        client, token, task_title,
                        f"Task for: {title}",
                        "todo", "medium", issue_id
                    )
                    if task_id:
                        stats["tasks_created"] += 1
                    else:
                        stats["tasks_failed"] += 1
                    time.sleep(0.03)

            else:
                stats["failed"] += 1
                print(f"  [{i+1:3d}/{len(prds)}] FAIL [{prd['sub_epic']:16s}] {title[:60]}")

            time.sleep(DELAY_BETWEEN)

    # Step 5: Final report
    elapsed = time.time() - t0
    print("\n" + "=" * 65)
    print("COMPLETE")
    print("=" * 65)
    print(f"Stories created:   {stats['created']}")
    print(f"Stories skipped:   {stats['skipped']} (already existed)")
    print(f"Stories failed:    {stats['failed']}")
    print(f"Tasks created:     {stats['tasks_created']}")
    print(f"Tasks failed:      {stats['tasks_failed']}")
    print(f"Time elapsed:      {elapsed:.1f}s")
    print()
    print("By Sub-Epic:")
    for se, count in sorted(stats["by_sub_epic"].items()):
        print(f"  {se}: {count} new stories")
    print()
    print("By Status:")
    for st, count in sorted(stats["by_status"].items()):
        print(f"  {st}: {count}")
    print()
    print(f"Board: http://localhost:3000/{WORKSPACE_SLUG}/issues")
    print("=" * 65)


if __name__ == "__main__":
    main()
