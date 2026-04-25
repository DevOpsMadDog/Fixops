#!/usr/bin/env python3
"""
Multica board sync for session 2026-04-25 (Beast Mode close).

Reads commits from the current session and:
  1. Closes existing open stories whose titles match commit subjects (status -> done).
  2. Creates new stories for tonight's session work that has no story yet.
  3. Tags every touched issue with label `session-2026-04-25-close`.
  4. Dumps the full plan + result to .omc/multica-pending-2026-04-25.json
     so we have an idempotent record (and a fallback for offline next runs).
  5. Computes aggregate burndown and prints final state.

Idempotent: re-running will skip already-done closes and dedup created stories
by title. Safe to run repeatedly.
"""

import json
import sys
import uuid
import psycopg2
from datetime import datetime, timezone
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────────────────────

WORKSPACE_ID = "30fad00d-8273-4196-96d4-abd55f4cbb43"
WORKSPACE_SLUG = "aldeci"
USER_ID = "251f9fe6-613f-4beb-98aa-f718c581bc59"

SESSION_TAG = "session-2026-04-25-close"
JSON_DUMP = Path("/Users/devops.ai/fixops/Fixops/.omc/multica-pending-2026-04-25.json")

# Existing Sub-Epic IDs on the board (parent for new stories)
SUB_EPIC_IDS = {
    "ASPM":            "c2780bde-481a-4ebd-ae2a-ffca31edb4f8",
    "CSPM":            "6eeac7b2-04a3-4c60-814b-9fd373463392",
    "CTEM":            "29c8fc83-add1-4357-8b1d-3424d1c97cd9",
    "SOC":             "9ead5b4a-7bb5-4c4d-931a-247beaa4ff51",
    "GRC":             "17f6c695-75ca-4949-954a-86de65dd58c0",
    "Identity":        "98f05b40-fa8c-45b4-ab2c-a6a46aa1fa10",
    "Network":         "1ad89985-951b-47e3-9105-60e7211bac45",
    "AI Intelligence": "c389e04b-0361-4942-ade8-f54d6e5771b4",
    "Executive":       "15c4969e-d690-47a5-b7d2-fc272928ca9b",
    "Advanced":        "7f6a4a63-a5ff-481d-8527-a23f644159d9",
}

# Existing open issue titles → close them (because session work covers them).
# (Only ones we positively confirmed via DB query, no false-positive closes.)
CLOSE_TITLES_EXACT = {
    "Fix frontend pages still showing mock instead of real data": "mock conversion in 16 pages + bulk A1+A2+A4 waves (commit 471bcc4b/389494993/41262073/00fd3e4b)",
    "Implement endpoint GET /api/v1/openapi.json (6h)":            "openapi.json catch-all fix (commit 5906bba4)",
}

# New stories to create. Each: title, description, status, priority, sub_epic.
NEW_STORIES = [
    # Real-tenant onboarding & seeding (tonight's session, completed)
    {
        "title": "Real-tenant onboarding — 15 GitHub apps as live tenants",
        "description": (
            "Onboard 15 famous open-source GitHub apps as live ALDECI tenants "
            "(no mock data). Used as the canonical scan substrate for this session. "
            "**Done** — see commits b138b2c3, 1ebcde31, 4ba499db, e5ee5f43.\n\n"
            "Closes 3 P1 onboarding bugs surfaced by the 15-tenant report."
        ),
        "status": "done", "priority": "high", "sub_epic": "ASPM",
    },
    {
        "title": "SAST → SecurityFindingsEngine bridge",
        "description": (
            "Bridge SAST scanner output into SecurityFindingsEngine so all SAST hits "
            "land in the unified findings queue. Mirrored alongside Brain Pipeline path."
        ),
        "status": "done", "priority": "high", "sub_epic": "ASPM",
    },
    {
        "title": "Brain Pipeline → SecurityFindingsEngine mirror",
        "description": (
            "Every Brain Pipeline output (12-step pipeline) is now mirrored into "
            "SecurityFindingsEngine. Verified via secrets scan + dep-graph commits "
            "(e5ee5f43, 4ba499db)."
        ),
        "status": "done", "priority": "high", "sub_epic": "CTEM",
    },
    {
        "title": "openapi.json catch-all route order fix",
        "description": (
            "/openapi.json alias was being shadowed by a catch-all route. Fixed "
            "registration order so the alias resolves first (commit 5906bba4)."
        ),
        "status": "done", "priority": "high", "sub_epic": "Advanced",
    },
    {
        "title": "/api/v1/auth/dev-token endpoint (FIXOPS_DEV_MODE-gated)",
        "description": (
            "Dev-only token endpoint that issues a short-lived bearer when "
            "FIXOPS_DEV_MODE=1. Unblocks Playwright NO MOCKS verification. "
            "Off in prod (commit 84bac9b8)."
        ),
        "status": "done", "priority": "high", "sub_epic": "Identity",
    },
    {
        "title": "16-page UI bulk mock → live API conversion",
        "description": (
            "Converted 16 mock-backed UI pages to live API calls "
            "(commit 471bcc4b after cherry-pick + persistence verification). "
            "Companion to A1/A2/A4 bulk waves (~80 pages total)."
        ),
        "status": "done", "priority": "high", "sub_epic": "Advanced",
    },
    {
        "title": "165-route Playwright visual verification",
        "description": (
            "Captured 165 route screenshots in a single visual-verify pass to "
            "establish the NO MOCKS baseline (commit a4063294)."
        ),
        "status": "done", "priority": "medium", "sub_epic": "Advanced",
    },
    {
        "title": "Per-tenant CVE + EPSS + KEV enrichment (15 tenants)",
        "description": (
            "Real-path enrichment of dependencies for all 15 onboarded tenants "
            "with CVE+EPSS+KEV. No synthetic data (commit 1ebcde31)."
        ),
        "status": "done", "priority": "high", "sub_epic": "CTEM",
    },
    {
        "title": "Per-tenant secrets scanning + SecurityFindingsEngine mirror",
        "description": (
            "Secrets scanner ran across 15 tenants via the real path; findings "
            "mirrored into SecurityFindingsEngine (commit e5ee5f43)."
        ),
        "status": "done", "priority": "high", "sub_epic": "ASPM",
    },
    {
        "title": "Per-tenant dependency graphs + arch classification",
        "description": (
            "Built dependency graphs and architecture classification for all 15 "
            "tenants via the real path (commit 4ba499db)."
        ),
        "status": "done", "priority": "high", "sub_epic": "ASPM",
    },
    {
        "title": "Per-tenant SBOM generation (CycloneDX/SPDX)",
        "description": (
            "Generated SBOMs for the 15 tenants and unblocked the SBOMExportDashboard "
            "live wiring (commit 411f0297). Companion fix in vendor-sbom-live-api merge."
        ),
        "status": "done", "priority": "medium", "sub_epic": "ASPM",
    },

    # 8 OSS-tool integration waves (in flight tonight)
    {
        "title": "OSS Tool Wave 1 — Snyk-equivalent (SAST/SCA) integration",
        "description": "Native Snyk-equiv ingest path. In flight tonight.",
        "status": "in_progress", "priority": "high", "sub_epic": "ASPM",
    },
    {
        "title": "OSS Tool Wave 2 — CSPM (open-source) integration",
        "description": "OSS CSPM tool (e.g. Prowler/ScoutSuite) ingest. In flight tonight.",
        "status": "in_progress", "priority": "high", "sub_epic": "CSPM",
    },
    {
        "title": "OSS Tool Wave 3 — EDR/XDR integration",
        "description": "OSS EDR/XDR signal ingest into SOC. In flight tonight.",
        "status": "in_progress", "priority": "high", "sub_epic": "SOC",
    },
    {
        "title": "OSS Tool Wave 4 — SIEM ingest integration",
        "description": "Open-source SIEM (Wazuh/Graylog) event bridge. In flight tonight.",
        "status": "in_progress", "priority": "high", "sub_epic": "SOC",
    },
    {
        "title": "OSS Tool Wave 5 — Container scan integration",
        "description": "Trivy/Grype-style container scanner ingest. In flight tonight.",
        "status": "in_progress", "priority": "high", "sub_epic": "ASPM",
    },
    {
        "title": "OSS Tool Wave 6 — IAM tool integration",
        "description": "OSS IAM analyzer (e.g. Cloudsplaining) ingest. In flight tonight.",
        "status": "in_progress", "priority": "high", "sub_epic": "Identity",
    },
    {
        "title": "OSS Tool Wave 7 — ThreatIntel feed integration",
        "description": "Additional OSS ThreatIntel feeds (MISP/OpenCTI) ingest. In flight tonight.",
        "status": "in_progress", "priority": "high", "sub_epic": "AI Intelligence",
    },
    {
        "title": "OSS Tool Wave 8 — DAST integration",
        "description": "OSS DAST scanner (ZAP/Nuclei) ingest. In flight tonight.",
        "status": "in_progress", "priority": "high", "sub_epic": "ASPM",
    },

    # Platform / process work
    {
        "title": "TrustGraph integration-topology meta-graph",
        "description": (
            "Build a TrustGraph meta-graph that maps every integration "
            "(connector, scanner, feed, OSS tool wave) to its emit/consume edges. "
            "In flight tonight."
        ),
        "status": "in_progress", "priority": "high", "sub_epic": "AI Intelligence",
    },
    {
        "title": "CLAUDE.md optimization — relocate wave history (1567 → 495 lines)",
        "description": (
            "Moved Wave 6–60 history from CLAUDE.md to docs/SESSION_HISTORY.md to "
            "shrink the live operating manual ~3x (commit 98fd247d)."
        ),
        "status": "done", "priority": "medium", "sub_epic": "Advanced",
    },
    {
        "title": "NO MOCKS rule — Playwright MCP gate",
        "description": (
            "Established hard rule: a UI task is not 'done' until Playwright MCP "
            "verifies it renders real data, not a mock (commit f66ee1c8)."
        ),
        "status": "done", "priority": "high", "sub_epic": "Advanced",
    },
]


# ── Helpers ────────────────────────────────────────────────────────────────────

def db():
    return psycopg2.connect(
        host="localhost", port=5433, dbname="multica",
        user="multica", password="multica", connect_timeout=10,
    )


def ensure_label(cur, name: str) -> str:
    cur.execute(
        "SELECT id FROM issue_label WHERE workspace_id=%s AND name=%s",
        (WORKSPACE_ID, name),
    )
    row = cur.fetchone()
    if row:
        return row[0]
    new_id = str(uuid.uuid4())
    cur.execute(
        "INSERT INTO issue_label (id, workspace_id, name, color) VALUES (%s,%s,%s,%s)",
        (new_id, WORKSPACE_ID, name, "#7c3aed"),
    )
    return new_id


def attach_label(cur, issue_id: str, label_id: str):
    cur.execute(
        "INSERT INTO issue_to_label (issue_id, label_id) VALUES (%s,%s) "
        "ON CONFLICT DO NOTHING",
        (issue_id, label_id),
    )


def burndown(cur):
    cur.execute("SELECT status, COUNT(*) FROM issue WHERE workspace_id=%s GROUP BY status", (WORKSPACE_ID,))
    return dict(cur.fetchall())


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    report = {
        "session": SESSION_TAG,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "workspace": WORKSPACE_SLUG,
        "burndown_before": {},
        "closed": [],
        "skipped_closes": [],
        "created": [],
        "skipped_creates": [],
        "errors": [],
        "burndown_after": {},
        "board_url": f"http://localhost:3000/{WORKSPACE_SLUG}/issues",
    }

    try:
        with db() as conn:
            with conn.cursor() as cur:
                report["burndown_before"] = burndown(cur)

                # 0. Ensure session label exists
                label_id = ensure_label(cur, SESSION_TAG)

                # 1. Close existing matching stories
                for title, why in CLOSE_TITLES_EXACT.items():
                    cur.execute(
                        "SELECT id, status FROM issue WHERE workspace_id=%s AND title=%s",
                        (WORKSPACE_ID, title),
                    )
                    row = cur.fetchone()
                    if not row:
                        report["skipped_closes"].append({"title": title, "reason": "not found"})
                        continue
                    iid, st = row
                    if st == "done":
                        attach_label(cur, iid, label_id)
                        report["skipped_closes"].append({"title": title, "id": iid, "reason": "already done"})
                        continue
                    cur.execute(
                        "UPDATE issue SET status='done', updated_at=NOW() WHERE id=%s",
                        (iid,),
                    )
                    attach_label(cur, iid, label_id)
                    report["closed"].append({"id": iid, "title": title, "from": st, "why": why})

                # 2. Create new stories (dedup by title within workspace)
                # Get next issue number for this workspace
                cur.execute(
                    "SELECT COALESCE(MAX(number), 0) FROM issue WHERE workspace_id=%s",
                    (WORKSPACE_ID,),
                )
                next_number = (cur.fetchone()[0] or 0) + 1

                for spec in NEW_STORIES:
                    cur.execute(
                        "SELECT id, status FROM issue WHERE workspace_id=%s AND title=%s",
                        (WORKSPACE_ID, spec["title"]),
                    )
                    row = cur.fetchone()
                    if row:
                        iid, st = row
                        # Bring status in line with our intent
                        if st != spec["status"]:
                            cur.execute(
                                "UPDATE issue SET status=%s, updated_at=NOW() WHERE id=%s",
                                (spec["status"], iid),
                            )
                        attach_label(cur, iid, label_id)
                        report["skipped_creates"].append(
                            {"title": spec["title"], "id": iid, "reason": "exists, status reconciled"}
                        )
                        continue

                    new_id = str(uuid.uuid4())
                    parent_id = SUB_EPIC_IDS.get(spec["sub_epic"], SUB_EPIC_IDS["Advanced"])
                    cur.execute(
                        """
                        INSERT INTO issue
                            (id, workspace_id, title, description, status, priority,
                             creator_type, creator_id, parent_issue_id, number, position,
                             created_at, updated_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, NOW(), NOW())
                        """,
                        (
                            new_id, WORKSPACE_ID,
                            spec["title"], spec["description"],
                            spec["status"], spec["priority"],
                            "member", USER_ID, parent_id,
                            next_number, 0.0,
                        ),
                    )
                    next_number += 1
                    attach_label(cur, new_id, label_id)
                    report["created"].append({
                        "id": new_id, "title": spec["title"],
                        "status": spec["status"], "priority": spec["priority"],
                        "sub_epic": spec["sub_epic"],
                    })

                conn.commit()
                report["burndown_after"] = burndown(cur)

    except Exception as e:
        report["errors"].append(repr(e))

    # 3. Dump JSON record
    JSON_DUMP.parent.mkdir(parents=True, exist_ok=True)
    JSON_DUMP.write_text(json.dumps(report, indent=2))

    # 4. Console summary
    print("=" * 70)
    print(f"MULTICA SYNC — {SESSION_TAG}")
    print("=" * 70)
    print(f"Closed:           {len(report['closed'])}")
    print(f"Skipped closes:   {len(report['skipped_closes'])}")
    print(f"Created:          {len(report['created'])}")
    print(f"Skipped creates:  {len(report['skipped_creates'])}")
    print(f"Errors:           {len(report['errors'])}")
    print(f"Burndown before:  {report['burndown_before']}")
    print(f"Burndown after:   {report['burndown_after']}")
    print(f"Snapshot:         {JSON_DUMP}")
    print(f"Board:            {report['board_url']}")
    if report["errors"]:
        print("ERRORS:")
        for e in report["errors"]:
            print(" ", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
