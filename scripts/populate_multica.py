#!/usr/bin/env python3
"""Populate Multica board with ALDECI issues from PRD files."""

import json
import os
import time
import urllib.request
import urllib.error

TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJlYXN0QGFsZGVjaS5pbyIsImV4cCI6MTc3OTAxNjY1MywiaWF0IjoxNzc2NDI0NjUzLCJuYW1lIjoiQmVhc3QgQWRtaW4iLCJzdWIiOiIyNTFmOWZlNi02MTNmLTRiZWItOThhYS1mNzE4YzU4MWJjNTkifQ.VZI_OrdpEudpl4xqrLvm9XJw0_0ud5IpFHXO_0J5FZQ"
BASE_URL = "http://localhost:8080/api"
WORKSPACE_SLUG = "aldeci"
PRD_DIR = "/Users/devops.ai/fixops/Fixops/.omc/prds"
MAIN_PRD = "/Users/devops.ai/fixops/Fixops/.omc/prd.json"


def api_post(path, data):
    url = f"{BASE_URL}{path}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode()}


def map_priority(p):
    """Map PRD priority to Multica priority."""
    if not p:
        return "medium"
    p = str(p).upper()
    if p in ("CRITICAL", "HIGH", "P1", "1"):
        return "high"
    if p in ("MEDIUM", "P2", "P3", "2", "3"):
        return "medium"
    if p in ("LOW", "P4", "4"):
        return "low"
    return "medium"


def map_status(current_state):
    """Map PRD current_state to Multica status."""
    if not current_state:
        return "todo"
    s = str(current_state).upper()
    if s in ("DONE", "COMPLETE", "COMPLETED", "IMPLEMENTED", "PRODUCTION"):
        return "done"
    if s in ("IN_PROGRESS", "IN PROGRESS", "WIP", "ACTIVE", "PARTIAL"):
        return "in_progress"
    # CRUD_ONLY, PLANNED, STUB, etc.
    return "todo"


def build_description(prd):
    """Build a rich markdown description from PRD fields."""
    parts = []

    desc = prd.get("description") or prd.get("summary") or ""
    if desc:
        parts.append(desc)

    # Flow PRDs
    if "flow_name" in prd:
        parts.append(f"\n**Flow:** `{prd['flow_name']}`")
        if prd.get("handler_location"):
            parts.append(f"**Handler:** `{prd['handler_location']}`")
        if prd.get("engines_involved"):
            engines = ", ".join(e["engine"] for e in prd["engines_involved"])
            parts.append(f"**Engines:** {engines}")
        if prd.get("what_works"):
            parts.append("\n**What works:**")
            for w in prd["what_works"]:
                parts.append(f"- {w}")
        if prd.get("what_doesnt"):
            parts.append("\n**What doesn't work:**")
            for w in prd["what_doesnt"]:
                parts.append(f"- {w}")

    # Community/domain PRDs
    if prd.get("domain") and prd["domain"] != "unknown":
        parts.append(f"\n**Domain:** {prd['domain']}")
    if prd.get("node_count"):
        parts.append(f"**Node count:** {prd['node_count']}")
    if prd.get("missing"):
        parts.append("\n**Missing:**")
        for m in prd["missing"]:
            parts.append(f"- {m}")
    if prd.get("connections_needed"):
        parts.append("\n**Connections needed:**")
        for c in prd["connections_needed"]:
            parts.append(f"- {c}")

    # Acceptance criteria
    if prd.get("acceptance_criteria"):
        parts.append("\n**Acceptance Criteria:**")
        for ac in prd["acceptance_criteria"]:
            parts.append(f"- {ac}")

    return "\n".join(parts)


def create_issue(title, description, priority, status):
    """Create a single issue on the Multica board."""
    result = api_post(
        f"/issues?workspace_slug={WORKSPACE_SLUG}",
        {
            "title": title,
            "description": description,
            "priority": priority,
            "status": status,
        },
    )
    return result


def load_prd_files():
    """Load all PRD files from the prds directory."""
    prds = []

    # Load community and flow PRDs
    for fname in sorted(os.listdir(PRD_DIR)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(PRD_DIR, fname)
        with open(fpath) as f:
            prd = json.load(f)
        prds.append((fname, prd))

    return prds


def load_main_prd():
    """Load the main prd.json (user stories)."""
    with open(MAIN_PRD) as f:
        return json.load(f)


def main():
    created = 0
    failed = 0
    by_status = {"todo": 0, "in_progress": 0, "done": 0}

    print("=== Loading PRD files ===")
    prd_files = load_prd_files()
    print(f"Found {len(prd_files)} PRD files in {PRD_DIR}")

    # Also load main prd.json stories
    main_prd = load_main_prd()
    print(f"Found main prd.json with {len(main_prd.get('stories', []))} stories")

    print("\n=== Creating issues from PRD files ===")

    for fname, prd in prd_files:
        title = prd.get("title") or prd.get("flow_name") or fname.replace(".json", "")
        # Prepend flow tag for flow PRDs
        if "flow_name" in prd:
            title = f"[Flow] {prd['flow_name']} — Cross-Category Event Handler"

        description = build_description(prd)
        priority = map_priority(prd.get("priority"))

        # Determine status from current_state
        cs = prd.get("current_state")
        if isinstance(cs, dict):
            # Flow PRDs have current_state as dict
            status = "in_progress"
        else:
            status = map_status(cs)

        result = create_issue(title, description, priority, status)

        if "error" in result:
            print(f"  FAIL [{fname}]: {result['error']}")
            failed += 1
        else:
            identifier = result.get("identifier", "?")
            print(f"  OK   {identifier}: {title[:70]}")
            created += 1
            by_status[status] = by_status.get(status, 0) + 1

        time.sleep(0.05)  # small delay to avoid hammering

    print("\n=== Creating issues from main prd.json stories ===")

    # Main prd stories — map passes=True → done, else todo
    for story in main_prd.get("stories", []):
        title = f"[Story] {story.get('id', '')}: {story.get('title', 'Untitled')}"
        status = "done" if story.get("passes") else "todo"
        priority = map_priority(story.get("priority"))

        ac = story.get("acceptanceCriteria", [])
        description = f"**Priority:** {story.get('priority')}\n\n**Acceptance Criteria:**\n"
        description += "\n".join(f"- {a}" for a in ac)

        result = create_issue(title, description, priority, status)

        if "error" in result:
            print(f"  FAIL [{story.get('id')}]: {result['error']}")
            failed += 1
        else:
            identifier = result.get("identifier", "?")
            print(f"  OK   {identifier}: {title[:70]}")
            created += 1
            by_status[status] = by_status.get(status, 0) + 1

        time.sleep(0.05)

    print("\n=== Summary ===")
    print(f"Total issues created: {created}")
    print(f"Failed:               {failed}")
    print(f"By status:")
    for s, count in by_status.items():
        print(f"  {s}: {count}")


if __name__ == "__main__":
    main()
