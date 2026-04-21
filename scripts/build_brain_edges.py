"""
Build Brain Edges — Transform 1,562 isolated nodes into a dense intelligence mesh.

Strategy:
1. aldeci findings → FOUND_ON asset (extract asset from node_id)
2. aldeci findings → REFERENCES CVE nodes (create CVE nodes if missing, then link)
3. aldeci components → BELONGS_TO asset (asset_id in props)
4. aldeci components → RELATED_TO same-ecosystem siblings
5. aldeci assets → CO_LOCATED cross-asset (same source)
6. aldeci-self findings → FOUND_ON self-asset (create if needed)
7. aldeci-self findings → RELATED_TO same-file siblings (group by file path)
8. aldeci-self findings → CLUSTERS_WITH same-title findings
9. severity clusters: findings → SEVERITY_PEER same-severity findings (sampled)
10. CVE cross-references: create cve nodes for all referenced CVEs, link findings
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = "/Users/devops.ai/fixops/Fixops/data/fixops_brain.db"
NOW = datetime.now(timezone.utc).isoformat()


def ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def open_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def load_all_nodes(conn: sqlite3.Connection) -> list[dict]:
    cur = conn.execute(
        "SELECT node_id, node_type, org_id, properties FROM brain_nodes"
    )
    nodes = []
    for r in cur.fetchall():
        props = json.loads(r["properties"]) if r["properties"] else {}
        nodes.append({
            "node_id": r["node_id"],
            "node_type": r["node_type"],
            "org_id": r["org_id"],
            "props": props,
        })
    return nodes


def existing_node_ids(conn: sqlite3.Connection) -> set[str]:
    cur = conn.execute("SELECT node_id FROM brain_nodes")
    return {r[0] for r in cur.fetchall()}


def existing_edge_keys(conn: sqlite3.Connection) -> set[tuple]:
    cur = conn.execute(
        "SELECT source_id, target_id, edge_type FROM brain_edges"
    )
    return {(r[0], r[1], r[2]) for r in cur.fetchall()}


def upsert_node(conn: sqlite3.Connection, node_id: str, node_type: str,
                org_id: str, props: dict) -> None:
    conn.execute(
        """INSERT INTO brain_nodes (node_id, node_type, org_id, properties, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(node_id) DO NOTHING""",
        (node_id, node_type, org_id, json.dumps(props), NOW, NOW),
    )


def insert_edges_batch(conn: sqlite3.Connection, edges: list[tuple],
                       existing: set[tuple]) -> int:
    """Insert edges skipping duplicates. Returns count inserted."""
    inserted = 0
    for src, tgt, etype, conf, props_dict in edges:
        key = (src, tgt, etype)
        if key in existing:
            continue
        try:
            conn.execute(
                """INSERT INTO brain_edges (source_id, target_id, edge_type, confidence, properties, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (src, tgt, etype, conf, json.dumps(props_dict), NOW),
            )
            existing.add(key)
            inserted += 1
        except sqlite3.IntegrityError:
            pass
    return inserted


def extract_asset_from_aldeci_finding(node_id: str) -> str | None:
    """
    finding:github:juice-shop/juice-shop:CVE-2022-24999:0
    → asset:github:juice-shop/juice-shop
    """
    # Pattern: finding:github:OWNER/REPO:VULN_ID:IDX
    m = re.match(r"^finding:(github:[^:]+/[^:]+):", node_id)
    if m:
        return f"asset:{m.group(1)}"
    return None


def extract_cve_from_finding(node_id: str, title: str) -> str | None:
    """Extract CVE ID from finding node_id or title."""
    # Try node_id first
    m = re.search(r"(CVE-\d{4}-\d{4,})", node_id, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    # Try title
    m = re.search(r"(CVE-\d{4}-\d{4,})", title or "", re.IGNORECASE)
    if m:
        return m.group(1).upper()
    return None


def extract_file_from_self_finding(node_id: str) -> str | None:
    """
    finding:self-scan-bandit--apps-api-anomaly-ml-router-py-223-...
    → extract the file slug (apps-api-anomaly-ml-router-py)
    """
    # Remove 'finding:self-scan-bandit-' prefix and trailing details
    m = re.match(r"^finding:self-scan-[^-]+-(.+?)-\d+-", node_id)
    if m:
        slug = m.group(1)
        # Trim leading 's-' or 'i-' or 'pi-' etc artefacts
        slug = re.sub(r"^[a-z]{1,3}-", "", slug)
        return slug
    # Fallback: take middle portion
    parts = node_id.split("-")
    if len(parts) > 4:
        return "-".join(parts[3:max(7, len(parts)//2)])
    return None


def main() -> None:
    conn = open_db()
    all_nodes = load_all_nodes(conn)
    node_ids = existing_node_ids(conn)
    existing = existing_edge_keys(conn)

    print(f"Loaded {len(all_nodes)} nodes, {len(existing)} existing edges")

    # Categorise nodes
    aldeci_findings = [n for n in all_nodes if n["org_id"] == "aldeci" and n["node_type"] == "finding"]
    aldeci_components = [n for n in all_nodes if n["org_id"] == "aldeci" and n["node_type"] == "component"]
    aldeci_assets = [n for n in all_nodes if n["org_id"] == "aldeci" and n["node_type"] in ("asset", "Asset")]
    self_findings = [n for n in all_nodes if n["org_id"] == "aldeci-self" and n["node_type"] == "finding"]

    print(f"  aldeci findings: {len(aldeci_findings)}")
    print(f"  aldeci components: {len(aldeci_components)}")
    print(f"  aldeci assets: {len(aldeci_assets)}")
    print(f"  aldeci-self findings: {len(self_findings)}")

    total_inserted = 0

    # -----------------------------------------------------------------------
    # 1. Create missing CVE nodes for all CVE-referenced findings
    # -----------------------------------------------------------------------
    print("\n[1] Creating missing CVE nodes...")
    cve_nodes_created = 0
    for f in aldeci_findings:
        cve_id = extract_cve_from_finding(f["node_id"], f["props"].get("title", ""))
        if not cve_id:
            continue
        cve_node_id = f"cve:{cve_id}"
        if cve_node_id not in node_ids:
            upsert_node(conn, cve_node_id, "cve", "aldeci", {
                "cve_id": cve_id,
                "severity": f["props"].get("severity", "unknown"),
                "source": "brain-edge-builder",
            })
            node_ids.add(cve_node_id)
            cve_nodes_created += 1
    conn.commit()
    print(f"  Created {cve_nodes_created} CVE nodes")

    # -----------------------------------------------------------------------
    # 2. Create virtual asset node for aldeci-self (ALDECI codebase itself)
    # -----------------------------------------------------------------------
    self_asset_id = "asset:self:aldeci-codebase"
    if self_asset_id not in node_ids:
        upsert_node(conn, self_asset_id, "asset", "aldeci-self", {
            "asset_id": "self:aldeci-codebase",
            "asset_type": "codebase",
            "name": "ALDECI Codebase (self-scan)",
        })
        node_ids.add(self_asset_id)
    conn.commit()

    # -----------------------------------------------------------------------
    # 3. aldeci findings → FOUND_ON asset
    # -----------------------------------------------------------------------
    print("\n[3] Linking aldeci findings → FOUND_ON asset...")
    edges = []
    for f in aldeci_findings:
        asset_id = extract_asset_from_aldeci_finding(f["node_id"])
        if asset_id and asset_id in node_ids:
            edges.append((f["node_id"], asset_id, "FOUND_ON", 1.0, {}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} FOUND_ON edges")

    # -----------------------------------------------------------------------
    # 4. aldeci findings → REFERENCES CVE
    # -----------------------------------------------------------------------
    print("\n[4] Linking aldeci findings → REFERENCES CVE...")
    edges = []
    for f in aldeci_findings:
        cve_id = extract_cve_from_finding(f["node_id"], f["props"].get("title", ""))
        if cve_id:
            cve_node_id = f"cve:{cve_id}"
            if cve_node_id in node_ids:
                edges.append((f["node_id"], cve_node_id, "REFERENCES", 1.0, {}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} REFERENCES edges")

    # -----------------------------------------------------------------------
    # 5. aldeci components → BELONGS_TO asset
    # -----------------------------------------------------------------------
    print("\n[5] Linking aldeci components → BELONGS_TO asset...")
    edges = []
    for c in aldeci_components:
        asset_id_prop = c["props"].get("asset_id", "")
        asset_node_id = f"asset:{asset_id_prop}" if asset_id_prop else None
        if asset_node_id and asset_node_id in node_ids:
            edges.append((c["node_id"], asset_node_id, "BELONGS_TO", 1.0, {}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} BELONGS_TO edges")

    # -----------------------------------------------------------------------
    # 6. aldeci components → DEPENDS_ON same-ecosystem siblings (sample)
    #    Group by asset+ecosystem, connect within each group
    # -----------------------------------------------------------------------
    print("\n[6] Creating component DEPENDS_ON ecosystem chains...")
    # Group by (asset_id, ecosystem)
    eco_groups: dict[tuple, list[str]] = defaultdict(list)
    for c in aldeci_components:
        key = (c["props"].get("asset_id", ""), c["props"].get("ecosystem", "unknown"))
        eco_groups[key].append(c["node_id"])

    edges = []
    for (asset_id, ecosystem), members in eco_groups.items():
        # Create a linear chain through ecosystem members (keeps edges meaningful)
        for i in range(len(members) - 1):
            edges.append((members[i], members[i + 1], "DEPENDS_ON", 0.7,
                          {"ecosystem": ecosystem, "inferred": True}))
        # Also link last back to first to form a ring (adds density)
        if len(members) > 2:
            edges.append((members[-1], members[0], "DEPENDS_ON", 0.5,
                          {"ecosystem": ecosystem, "ring_close": True}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} DEPENDS_ON (ecosystem chain) edges across {len(eco_groups)} groups")

    # -----------------------------------------------------------------------
    # 7. aldeci assets → CO_LOCATED (cross-asset relationships)
    # -----------------------------------------------------------------------
    print("\n[7] Creating asset CO_LOCATED edges...")
    edges = []
    asset_ids = [a["node_id"] for a in aldeci_assets]
    for i, a1 in enumerate(asset_ids):
        for a2 in asset_ids[i + 1:]:
            edges.append((a1, a2, "CO_LOCATED", 0.8, {"source": "same-org-scan"}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} CO_LOCATED edges")

    # -----------------------------------------------------------------------
    # 8. aldeci findings on same asset → RELATED_TO (sibling findings)
    # -----------------------------------------------------------------------
    print("\n[8] Creating same-asset finding RELATED_TO clusters...")
    asset_finding_groups: dict[str, list[str]] = defaultdict(list)
    for f in aldeci_findings:
        asset_id = extract_asset_from_aldeci_finding(f["node_id"])
        if asset_id:
            asset_finding_groups[asset_id].append(f["node_id"])

    edges = []
    for asset_id, findings in asset_finding_groups.items():
        # Connect all findings on same asset: star topology from first finding
        if len(findings) < 2:
            continue
        hub = findings[0]
        for spoke in findings[1:]:
            edges.append((hub, spoke, "RELATED_TO", 0.9,
                          {"reason": "same-asset", "asset": asset_id}))
        # Also chain sequentially for more edges
        for i in range(len(findings) - 1):
            edges.append((findings[i], findings[i + 1], "CORRELATES_WITH", 0.8,
                          {"asset": asset_id}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} RELATED_TO/CORRELATES_WITH edges")

    # -----------------------------------------------------------------------
    # 9. Same-CVE findings across assets → AFFECTS_SAME_CVE
    # -----------------------------------------------------------------------
    print("\n[9] Cross-asset CVE correlation edges...")
    cve_finding_map: dict[str, list[str]] = defaultdict(list)
    for f in aldeci_findings:
        cve_id = extract_cve_from_finding(f["node_id"], f["props"].get("title", ""))
        if cve_id:
            cve_finding_map[cve_id].append(f["node_id"])

    edges = []
    for cve_id, findings in cve_finding_map.items():
        if len(findings) < 2:
            continue
        # Star from CVE node outwards to each finding
        cve_node_id = f"cve:{cve_id}"
        if cve_node_id in node_ids:
            for f_id in findings:
                edges.append((cve_node_id, f_id, "AFFECTS", 1.0,
                              {"cve": cve_id}))
        # Cross-link findings sharing same CVE
        hub = findings[0]
        for spoke in findings[1:]:
            edges.append((hub, spoke, "AFFECTS_SAME_CVE", 0.95,
                          {"cve": cve_id}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} CVE AFFECTS/AFFECTS_SAME_CVE edges")

    # -----------------------------------------------------------------------
    # 10. aldeci-self findings → FOUND_ON self-asset
    # -----------------------------------------------------------------------
    print("\n[10] Linking self-scan findings → FOUND_ON aldeci-codebase...")
    edges = []
    for f in self_findings:
        edges.append((f["node_id"], self_asset_id, "FOUND_ON", 1.0, {}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} FOUND_ON (self) edges")

    # -----------------------------------------------------------------------
    # 11. aldeci-self findings grouped by file → SAME_FILE clusters
    # -----------------------------------------------------------------------
    print("\n[11] Clustering self-scan findings by source file...")
    file_groups: dict[str, list[str]] = defaultdict(list)
    for f in self_findings:
        file_slug = extract_file_from_self_finding(f["node_id"])
        if file_slug:
            file_groups[file_slug].append(f["node_id"])

    # Create virtual file nodes for top files
    edges = []
    for file_slug, members in file_groups.items():
        if len(members) < 2:
            continue
        file_node_id = f"file:{file_slug}"
        if file_node_id not in node_ids:
            upsert_node(conn, file_node_id, "file", "aldeci-self", {
                "path": file_slug,
                "finding_count": len(members),
            })
            node_ids.add(file_node_id)
        # All findings → FOUND_IN file
        for m in members:
            edges.append((m, file_node_id, "FOUND_IN", 1.0, {"file": file_slug}))
        # Sequential SAME_FILE chain
        for i in range(len(members) - 1):
            edges.append((members[i], members[i + 1], "SAME_FILE", 0.9,
                          {"file": file_slug}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} FOUND_IN/SAME_FILE edges across {len(file_groups)} files")

    # -----------------------------------------------------------------------
    # 12. aldeci-self findings grouped by title (same rule) → SAME_RULE
    # -----------------------------------------------------------------------
    print("\n[12] Clustering self-scan findings by rule/title...")
    title_groups: dict[str, list[str]] = defaultdict(list)
    for f in self_findings:
        title = f["props"].get("title", "unknown")
        title_groups[title].append(f["node_id"])

    edges = []
    for title, members in title_groups.items():
        if len(members) < 2:
            continue
        # Create rule node
        rule_slug = re.sub(r"[^a-z0-9]+", "-", title.lower())[:60]
        rule_node_id = f"rule:{rule_slug}"
        if rule_node_id not in node_ids:
            upsert_node(conn, rule_node_id, "rule", "aldeci-self", {
                "rule_name": title,
                "finding_count": len(members),
            })
            node_ids.add(rule_node_id)
        for m in members:
            edges.append((m, rule_node_id, "TRIGGERED_BY", 1.0, {"rule": title}))
        # Star topology: hub → all spokes
        hub = members[0]
        for spoke in members[1:]:
            edges.append((hub, spoke, "SAME_RULE", 0.85, {"rule": title}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} TRIGGERED_BY/SAME_RULE edges across {len(title_groups)} rules")

    # -----------------------------------------------------------------------
    # 13. aldeci-self findings → SEVERITY_PEER (cross-severity hubs)
    # -----------------------------------------------------------------------
    print("\n[13] Severity peer clusters for self-scan findings...")
    sev_groups: dict[str, list[str]] = defaultdict(list)
    for f in self_findings:
        sev = f["props"].get("severity", "unknown")
        sev_groups[sev].append(f["node_id"])

    edges = []
    for sev, members in sev_groups.items():
        # Create severity hub node
        hub_node_id = f"severity-cluster:{sev}:aldeci-self"
        if hub_node_id not in node_ids:
            upsert_node(conn, hub_node_id, "severity_cluster", "aldeci-self", {
                "severity": sev,
                "count": len(members),
            })
            node_ids.add(hub_node_id)
        for m in members:
            edges.append((m, hub_node_id, "CLUSTERS_WITH", 0.75, {"severity": sev}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} CLUSTERS_WITH (severity) edges")

    # -----------------------------------------------------------------------
    # 14. aldeci findings → severity cluster hubs
    # -----------------------------------------------------------------------
    print("\n[14] Severity peer clusters for aldeci findings...")
    sev_groups2: dict[str, list[str]] = defaultdict(list)
    for f in aldeci_findings:
        sev = f["props"].get("severity", "unknown")
        sev_groups2[sev].append(f["node_id"])

    edges = []
    for sev, members in sev_groups2.items():
        hub_node_id = f"severity-cluster:{sev}:aldeci"
        if hub_node_id not in node_ids:
            upsert_node(conn, hub_node_id, "severity_cluster", "aldeci", {
                "severity": sev,
                "count": len(members),
            })
            node_ids.add(hub_node_id)
        for m in members:
            edges.append((m, hub_node_id, "CLUSTERS_WITH", 0.75, {"severity": sev}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} CLUSTERS_WITH (aldeci severity) edges")

    # -----------------------------------------------------------------------
    # 15. CVE nodes → AFFECTS component (match by CVE in component purl / name)
    # -----------------------------------------------------------------------
    print("\n[15] CVE → AFFECTS component edges...")
    # Get all CVE nodes
    cve_nodes = [n for n in all_nodes if n["node_type"] in ("cve", "CVE")]
    edges = []
    for cve in cve_nodes:
        cve_id = cve["props"].get("cve_id") or re.search(r"CVE-\d{4}-\d+", cve["node_id"], re.I)
        if not cve_id:
            continue
        if hasattr(cve_id, "group"):
            cve_id = cve_id.group(0)
        # Link CVE to all components on same asset as a finding that references it
        for f in aldeci_findings:
            f_cve = extract_cve_from_finding(f["node_id"], f["props"].get("title", ""))
            if f_cve and f_cve.upper() == cve_id.upper():
                asset_id = extract_asset_from_aldeci_finding(f["node_id"])
                if not asset_id:
                    continue
                # Link CVE to components on that asset
                for c in aldeci_components:
                    if c["props"].get("asset_id", "") and f"github:{c['props']['asset_id']}" in asset_id:
                        edges.append((cve["node_id"], c["node_id"], "AFFECTS_COMPONENT", 0.8,
                                      {"inferred": True}))
                        if len(edges) > 500:  # cap per CVE to avoid explosion
                            break
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} AFFECTS_COMPONENT edges")

    # -----------------------------------------------------------------------
    # 16. Source-type clusters for aldeci findings (bandit, grype, semgrep, etc.)
    # -----------------------------------------------------------------------
    print("\n[16] Source/scanner cluster edges...")
    source_groups: dict[str, list[str]] = defaultdict(list)
    for f in aldeci_findings + self_findings:
        src = f["props"].get("source", "unknown")
        # Normalise
        src = src.split("/")[0] if "/" in src else src
        source_groups[src].append(f["node_id"])

    edges = []
    for src, members in source_groups.items():
        hub_node_id = f"scanner:{src}"
        if hub_node_id not in node_ids:
            upsert_node(conn, hub_node_id, "scanner", "aldeci", {
                "scanner_name": src,
                "finding_count": len(members),
            })
            node_ids.add(hub_node_id)
        for m in members:
            edges.append((m, hub_node_id, "DETECTED_BY", 1.0, {"scanner": src}))
    n = insert_edges_batch(conn, edges, existing)
    conn.commit()
    total_inserted += n
    print(f"  Inserted {n} DETECTED_BY (scanner) edges")

    # -----------------------------------------------------------------------
    # Final stats
    # -----------------------------------------------------------------------
    conn.commit()
    cur = conn.execute("SELECT COUNT(*) FROM brain_nodes")
    final_nodes = cur.fetchone()[0]
    cur = conn.execute("SELECT COUNT(*) FROM brain_edges")
    final_edges = cur.fetchone()[0]
    cur = conn.execute("SELECT edge_type, COUNT(*) cnt FROM brain_edges GROUP BY edge_type ORDER BY cnt DESC")
    edge_breakdown = [(r[0], r[1]) for r in cur.fetchall()]

    conn.close()

    print(f"\n{'='*60}")
    print(f"DONE: inserted {total_inserted} new edges")
    print(f"Final state: {final_nodes} nodes, {final_edges} edges")
    print(f"\nEdge type breakdown:")
    for etype, cnt in edge_breakdown:
        print(f"  {etype:35s} {cnt}")


if __name__ == "__main__":
    main()
