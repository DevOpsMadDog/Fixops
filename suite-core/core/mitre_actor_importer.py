"""MITRE ATT&CK threat-actor importer.

Pulls intrusion-set objects (real APT/criminal groups) from the public
MITRE ATT&CK STIX bundle and registers them as tracked actors via
ThreatActorTrackingEngine. NO fake/seed data — real public source only.

Source: https://github.com/mitre/cti  (Apache 2.0 licensed)
"""
from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
DEFAULT_TIMEOUT = 60  # 43MB bundle


def _classify_actor_type(group_name: str, aliases: List[str], description: str) -> str:
    """Classify intrusion-set into Aldeci's actor_type taxonomy.

    Valid actor types per ThreatActorTrackingEngine: nation-state, criminal,
    hacktivist, insider, unknown. We infer from MITRE description / name.
    """
    text = (group_name + " " + " ".join(aliases) + " " + description).lower()
    nation_state_signals = (
        "nation", "state-sponsored", "state sponsored", "apt", "intelligence",
        "russian", "chinese", "north korean", "iranian", "ministry", "gru",
        "fsb", "mss", "lazarus", "rgb",
    )
    criminal_signals = (
        "ransomware", "cybercrim", "criminal", "for profit", "financially",
        "extortion", "carbanak", "fin7", "fin6", "evil corp",
    )
    hacktivist_signals = ("hacktivist", "anonymous", "activism", "protest")

    if any(s in text for s in nation_state_signals):
        return "nation-state"
    if any(s in text for s in criminal_signals):
        return "criminal"
    if any(s in text for s in hacktivist_signals):
        return "hacktivist"
    return "unknown"


def _classify_threat_level(name: str, aliases: List[str], description: str) -> str:
    """Classify threat level (low/medium/high/critical)."""
    text = (name + " " + " ".join(aliases) + " " + description).lower()
    if any(k in text for k in ("apt", "lazarus", "cozy bear", "fancy bear",
                               "carbanak", "ransomware")):
        return "critical"
    if any(k in text for k in ("nation", "state sponsored", "fin7", "fin6",
                               "advanced", "sophisticated")):
        return "high"
    return "medium"


def _extract_country(description: str, aliases: List[str]) -> str:
    """Extract origin country code from description (best-effort)."""
    text = (description + " " + " ".join(aliases)).lower()
    mapping = {
        "russia": "RU", "russian": "RU",
        "china": "CN", "chinese": "CN",
        "north korea": "KP", "korean": "KP",
        "iran": "IR", "iranian": "IR",
        "ukraine": "UA", "ukrainian": "UA",
        "vietnam": "VN", "vietnamese": "VN",
        "india": "IN", "indian": "IN",
        "pakistan": "PK", "pakistani": "PK",
        "united states": "US", "american": "US",
    }
    for needle, code in mapping.items():
        if needle in text:
            return code
    return ""


def fetch_mitre_bundle(
    url: str = MITRE_ATTACK_URL,
    timeout: int = DEFAULT_TIMEOUT,
    cached_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch the MITRE ATT&CK STIX bundle (real public data).

    If cached_path is given and exists, load from there to avoid re-download
    in tests / repeat calls.
    """
    if cached_path:
        try:
            with open(cached_path, "rb") as fh:
                return json.loads(fh.read())
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.warning("Cache read failed (%s); falling back to network", exc)

    logger.info("Fetching MITRE ATT&CK bundle from %s", url)
    req = urllib.request.Request(
        url, headers={"User-Agent": "ALDECI/MITRE-Importer (+aldeci.security)"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    bundle = json.loads(raw)
    if cached_path:
        try:
            with open(cached_path, "wb") as fh:
                fh.write(raw)
        except Exception as exc:
            logger.warning("Cache write failed: %s", exc)
    return bundle


def extract_intrusion_sets(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract intrusion-set (threat actor) objects from a STIX bundle."""
    objs = bundle.get("objects", [])
    return [o for o in objs if o.get("type") == "intrusion-set"]


def import_mitre_actors(
    engine: Any,
    org_id: str,
    *,
    limit: Optional[int] = None,
    cached_path: Optional[str] = None,
    bundle: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Import MITRE ATT&CK groups as tracked actors for org_id.

    Idempotent at the actor_name level — won't import a duplicate name
    (queries existing actors first).

    Args:
        engine: ThreatActorTrackingEngine instance with track_actor + list_actors.
        org_id: Tenant slug.
        limit: Cap on number of actors to import (None = all).
        cached_path: Optional local cache path for the STIX bundle.
        bundle: If provided, skip network fetch and use this bundle directly.

    Returns:
        {imported: int, skipped_existing: int, errors: int, total_available: int,
         source: "mitre-attack-enterprise"}
    """
    if bundle is None:
        bundle = fetch_mitre_bundle(cached_path=cached_path)

    intrusion_sets = extract_intrusion_sets(bundle)
    total = len(intrusion_sets)

    # Get existing actor names to dedupe
    try:
        existing = engine.list_actors(org_id=org_id) or []
        existing_names = {a.get("actor_name", "").lower() for a in existing}
    except Exception as exc:
        logger.warning("list_actors failed (%s); proceeding without dedupe", exc)
        existing_names = set()

    imported = 0
    skipped = 0
    errors = 0
    imported_records: List[Dict[str, Any]] = []

    for grp in intrusion_sets:
        if limit is not None and imported >= limit:
            break
        name = (grp.get("name") or "").strip()
        if not name:
            continue
        if name.lower() in existing_names:
            skipped += 1
            continue

        aliases = list(grp.get("aliases") or [])
        # MITRE puts the name itself first in aliases; drop it
        aliases = [a for a in aliases if a.lower() != name.lower()]
        description = grp.get("description", "") or ""

        actor_type = _classify_actor_type(name, aliases, description)
        threat_level = _classify_threat_level(name, aliases, description)
        nation_state = _extract_country(description, aliases)
        # Extract MITRE group ID from external_references
        mitre_groups: List[str] = []
        for ref in grp.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                mitre_groups.append(ref["external_id"])
                break

        try:
            engine.track_actor(
                org_id=org_id,
                actor_name=name,
                actor_alias=", ".join(aliases[:5]),  # cap to 5 aliases
                nation_state=nation_state,
                actor_type=actor_type,
                threat_level=threat_level,
                targeting_our_sector=False,
                mitre_groups=mitre_groups,
            )
            imported += 1
            imported_records.append({
                "actor_name": name,
                "mitre_groups": mitre_groups,
                "actor_type": actor_type,
                "threat_level": threat_level,
                "nation_state": nation_state,
            })
        except Exception as exc:
            errors += 1
            logger.warning("Failed to import actor %s: %s", name, exc)

    return {
        "source": "mitre-attack-enterprise",
        "source_url": MITRE_ATTACK_URL,
        "imported": imported,
        "skipped_existing": skipped,
        "errors": errors,
        "total_available": total,
        "sample": imported_records[:10],
    }
