"""
GraphRAG Relationship Enrichment Script.

Seeds the TrustGraph KnowledgeStore with cross-entity relationships so
all 5 GraphRAG query templates return meaningful data:

  1. FINDING_AFFECTS_ASSET  — wires 225 findings to 58 assets
  2. violates_control       — wires findings to 40 compliance controls
  3. ThreatActor entities   — creates 10 named threat actors
  4. ACTOR_USES_TTP         — links actors to existing TTP entities
  5. ACTOR_TARGETS_ASSET    — links actors to assets they target

Run from the Fixops root:
    python scripts/enrich_graphrag_relationships.py
"""

import sys
import uuid
import random
from datetime import datetime, timezone
from typing import List

sys.path.insert(0, "suite-core")

from trustgraph.knowledge_store import (  # noqa: E402
    KnowledgeStore,
    KnowledgeEntity,
    KnowledgeRelationship,
)

CORE_ASSET = 1
CORE_SECURITY = 2
CORE_COMPLIANCE = 3

THREAT_ACTORS = [
    {"id": "actor_apt28", "name": "APT28 (Fancy Bear)", "nation": "Russia", "motivation": "espionage"},
    {"id": "actor_apt29", "name": "APT29 (Cozy Bear)", "nation": "Russia", "motivation": "espionage"},
    {"id": "actor_lazarus", "name": "Lazarus Group", "nation": "North Korea", "motivation": "financial"},
    {"id": "actor_sandworm", "name": "Sandworm Team", "nation": "Russia", "motivation": "disruption"},
    {"id": "actor_fin7", "name": "FIN7 (Carbanak)", "nation": "Unknown", "motivation": "financial"},
    {"id": "actor_revil", "name": "REvil (Sodinokibi)", "nation": "Unknown", "motivation": "ransomware"},
    {"id": "actor_lockbit", "name": "LockBit 3.0", "nation": "Unknown", "motivation": "ransomware"},
    {"id": "actor_scattered_spider", "name": "Scattered Spider", "nation": "Unknown", "motivation": "financial"},
    {"id": "actor_volt_typhoon", "name": "Volt Typhoon", "nation": "China", "motivation": "espionage"},
    {"id": "actor_blackcat", "name": "BlackCat (ALPHV)", "nation": "Unknown", "motivation": "ransomware"},
]

# Severity → which control categories map to it
SEVERITY_CONTROL_MAP = {
    "critical": ["CC6", "CC7", "CC8"],
    "high": ["CC6", "CC7", "A1"],
    "medium": ["CC2", "CC3", "CC4"],
    "low": ["CC1", "CC2"],
    "unknown": ["CC1"],
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_rel(source_id: str, target_id: str, rel_type: str) -> KnowledgeRelationship:
    return KnowledgeRelationship(
        rel_id=f"rel_{uuid.uuid4().hex[:12]}",
        source_id=source_id,
        target_id=target_id,
        rel_type=rel_type,
        confidence=1.0,
        properties={},
    )


def safe_add_rel(store: KnowledgeStore, source_id: str, target_id: str, rel_type: str) -> bool:
    try:
        store.add_relationship(make_rel(source_id, target_id, rel_type))
        return True
    except Exception as exc:
        print(f"  [warn] rel {rel_type} {source_id}->{target_id}: {exc}")
        return False


def main() -> None:
    random.seed(42)
    store = KnowledgeStore()
    print(f"KnowledgeStore DB: {store.db_path}")

    # ── Load existing entities ─────────────────────────────────────────────
    findings_raw = store.search(core_id=CORE_SECURITY, query_text="", limit=500)
    findings = [e for e in findings_raw if e.entity_type == "Finding"]

    assets_raw = store.search(core_id=CORE_ASSET, query_text="", limit=300)
    assets = [e for e in assets_raw if e.entity_type == "Asset"]

    controls_raw = store.search(core_id=CORE_COMPLIANCE, query_text="", limit=200)
    controls = [e for e in controls_raw if e.entity_type == "Control"]

    ttps_raw = store.search(core_id=CORE_SECURITY, query_text="", limit=100)
    ttps = [e for e in ttps_raw if e.entity_type == "TTP"]

    print(f"Loaded: {len(findings)} findings, {len(assets)} assets, "
          f"{len(controls)} controls, {len(ttps)} TTPs")

    if not findings:
        print("ERROR: No findings found. Run seed_demo_data.py first.")
        sys.exit(1)

    if not assets:
        print("ERROR: No assets found. Run seed_demo_data.py first.")
        sys.exit(1)

    # ── 1. FINDING_AFFECTS_ASSET ───────────────────────────────────────────
    print("\n[1/4] Creating FINDING_AFFECTS_ASSET relationships...")
    fa_count = 0
    for finding in findings:
        sev = (finding.properties or {}).get("severity", "unknown")
        n_assets = {"critical": 3, "high": 2, "medium": 2, "low": 1}.get(sev, 1)
        chosen = random.sample(assets, min(n_assets, len(assets)))
        for asset in chosen:
            if safe_add_rel(store, finding.entity_id, asset.entity_id, "FINDING_AFFECTS_ASSET"):
                fa_count += 1
    print(f"  Created {fa_count} FINDING_AFFECTS_ASSET relationships")

    # ── 2. violates_control ────────────────────────────────────────────────
    print("\n[2/4] Creating violates_control relationships...")
    # Build a lookup: control_id_fragment → control entity
    control_lookup: dict = {}
    for ctrl in controls:
        for fragment in SEVERITY_CONTROL_MAP.get("critical", []):
            if fragment in ctrl.entity_id:
                control_lookup.setdefault(fragment, []).append(ctrl)
        for sev_frags in SEVERITY_CONTROL_MAP.values():
            for fragment in sev_frags:
                if fragment in ctrl.entity_id:
                    control_lookup.setdefault(fragment, []).append(ctrl)

    vc_count = 0
    for finding in findings:
        sev = (finding.properties or {}).get("severity", "unknown")
        fragments = SEVERITY_CONTROL_MAP.get(sev, ["CC1"])
        for fragment in fragments:
            matched_controls = control_lookup.get(fragment, [])
            # Pick 1 control per fragment to avoid explosion
            if matched_controls:
                ctrl = random.choice(matched_controls)
                if safe_add_rel(store, finding.entity_id, ctrl.entity_id, "violates_control"):
                    vc_count += 1

    # Fallback: if control_lookup is empty, wire each finding to a random control
    if vc_count == 0 and controls:
        print("  Control lookup empty, using random fallback...")
        for finding in findings:
            ctrl = random.choice(controls)
            if safe_add_rel(store, finding.entity_id, ctrl.entity_id, "violates_control"):
                vc_count += 1

    print(f"  Created {vc_count} violates_control relationships")

    # ── 3. ThreatActor entities + ACTOR_USES_TTP + ACTOR_TARGETS_ASSET ────
    print("\n[3/4] Creating ThreatActor entities...")
    actor_count = 0
    for actor_def in THREAT_ACTORS:
        actor = KnowledgeEntity(
            entity_id=actor_def["id"],
            core_id=CORE_SECURITY,
            entity_type="ThreatActor",
            name=actor_def["name"],
            properties={
                "nation_state": actor_def["nation"],
                "motivation": actor_def["motivation"],
                "active": True,
                "confidence": 0.9,
                "indexed_at": now_iso(),
            },
            org_id="default",
        )
        try:
            store.ingest(actor)
            actor_count += 1
        except Exception as exc:
            print(f"  [warn] ingest actor {actor_def['id']}: {exc}")
    print(f"  Created {actor_count} ThreatActor entities")

    # Reload actors via get_entity (search fallback doesn't match them reliably)
    actors = []
    for actor_def in THREAT_ACTORS:
        entity = store.get_entity(actor_def["id"])
        if entity is not None:
            actors.append(entity)
    print(f"  Verified {len(actors)} ThreatActor entities in store")

    # ── 4. ACTOR_USES_TTP relationships ───────────────────────────────────
    print("\n[4/4] Creating ACTOR_USES_TTP and ACTOR_TARGETS_ASSET relationships...")
    ttp_count = 0
    target_count = 0

    for actor in actors:
        # Each actor uses 2-4 TTPs
        if ttps:
            n_ttps = random.randint(2, min(4, len(ttps)))
            chosen_ttps = random.sample(ttps, n_ttps)
            for ttp in chosen_ttps:
                if safe_add_rel(store, actor.entity_id, ttp.entity_id, "ACTOR_USES_TTP"):
                    ttp_count += 1

        # Each actor targets 3-6 assets
        n_targets = random.randint(3, min(6, len(assets)))
        chosen_assets = random.sample(assets, n_targets)
        for asset in chosen_assets:
            if safe_add_rel(store, actor.entity_id, asset.entity_id, "ACTOR_TARGETS_ASSET"):
                target_count += 1

    print(f"  Created {ttp_count} ACTOR_USES_TTP relationships")
    print(f"  Created {target_count} ACTOR_TARGETS_ASSET relationships")

    # ── Summary ────────────────────────────────────────────────────────────
    total = fa_count + vc_count + actor_count + ttp_count + target_count
    print(f"\n=== Enrichment complete: {total} total relationships/entities created ===")
    print(f"  FINDING_AFFECTS_ASSET: {fa_count}")
    print(f"  violates_control:      {vc_count}")
    print(f"  ThreatActor entities:  {actor_count}")
    print(f"  ACTOR_USES_TTP:        {ttp_count}")
    print(f"  ACTOR_TARGETS_ASSET:   {target_count}")


if __name__ == "__main__":
    main()
