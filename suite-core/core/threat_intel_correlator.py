"""
Threat Intelligence Correlation Engine — ALDECI.

Correlates security findings against known threat actor profiles and campaigns
using IOC (Indicator of Compromise) and TTP (Tactics, Techniques, Procedures)
matching. Backed by SQLite for persistence across sessions.

Features:
- Pydantic v2 models: ThreatActor, Campaign, ThreatCorrelation
- SQLite-backed ThreatIntelCorrelator with thread-safe operations
- 10 built-in APT threat actor profiles (APT29, APT41, Lazarus, etc.)
- Batch correlation for pipeline integration
- Threat landscape and campaign timeline queries

Compliance: MITRE ATT&CK framework, STIX/TAXII-compatible data shapes
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class ThreatActor(BaseModel):
    """
    Known threat actor (APT group, criminal org, nation-state).

    Attributes:
        id: Unique actor identifier (e.g. "apt29")
        name: Common name (e.g. "Cozy Bear")
        aliases: Known alternate names
        ttps: MITRE ATT&CK technique IDs (e.g. ["T1566", "T1078"])
        motivation: Primary motivation (espionage, financial, etc.)
        origin_country: Attributed country of origin
        active: Whether actor is currently active
        associated_campaigns: Campaign IDs linked to this actor
        iocs: Indicators of Compromise (IPs, domains, hashes, etc.)
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    aliases: List[str] = Field(default_factory=list)
    ttps: List[str] = Field(default_factory=list)
    motivation: str = "unknown"
    origin_country: Optional[str] = None
    active: bool = True
    associated_campaigns: List[str] = Field(default_factory=list)
    iocs: List[str] = Field(default_factory=list)


class Campaign(BaseModel):
    """
    Threat campaign linking actors to a coordinated attack effort.

    Attributes:
        id: Unique campaign identifier
        name: Campaign name
        threat_actor_id: ID of the responsible threat actor
        start_date: Campaign start date (ISO 8601)
        status: "active", "concluded", or "suspected"
        targets: Target sectors or org names
        iocs: Campaign-specific IOCs
        ttps: TTPs observed in this campaign
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    threat_actor_id: str
    start_date: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "active"
    targets: List[str] = Field(default_factory=list)
    iocs: List[str] = Field(default_factory=list)
    ttps: List[str] = Field(default_factory=list)


class ThreatCorrelation(BaseModel):
    """
    Result of correlating a finding against threat intelligence.

    Attributes:
        finding_id: The finding being correlated
        threat_actor: Matched threat actor (None if no match)
        campaign: Matched campaign (None if no match)
        confidence: Confidence score 0.0–1.0
        ioc_matches: IOCs from the finding that matched the actor/campaign
        ttp_matches: TTPs from the finding that matched the actor/campaign
    """

    finding_id: str
    threat_actor: Optional[ThreatActor] = None
    campaign: Optional[Campaign] = None
    confidence: float = 0.0
    ioc_matches: List[str] = Field(default_factory=list)
    ttp_matches: List[str] = Field(default_factory=list)


# ============================================================================
# BUILT-IN THREAT ACTOR PROFILES
# ============================================================================

_BUILTIN_ACTORS: List[Dict[str, Any]] = [
    {
        "id": "apt29",
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard", "IRON HEMLOCK"],
        "ttps": [
            "T1566", "T1078", "T1059", "T1486", "T1070", "T1105",
            "T1021", "T1550", "T1098", "T1190",
        ],
        "motivation": "espionage",
        "origin_country": "Russia",
        "active": True,
        "associated_campaigns": ["solarwinds-2020", "cozy-cloud-2023"],
        "iocs": [
            "185.220.101.0/24", "192.99.221.0/24",
            "evildomain.ru", "malicious-update.com",
            "3f3a9dba1f2b4c5d6e7f8a9b0c1d2e3f",
        ],
    },
    {
        "id": "apt41",
        "name": "APT41",
        "aliases": ["Double Dragon", "Winnti", "Barium", "Bronze Atlas"],
        "ttps": [
            "T1566", "T1190", "T1059", "T1486", "T1078", "T1021",
            "T1036", "T1027", "T1070", "T1055",
        ],
        "motivation": "espionage+financial",
        "origin_country": "China",
        "active": True,
        "associated_campaigns": ["operation-shadowhammer", "apt41-supply-chain-2021"],
        "iocs": [
            "45.77.0.0/16", "103.85.24.0/24",
            "update-service.cn", "cdn-proxy.net",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        ],
    },
    {
        "id": "lazarus",
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "Zinc", "Guardians of Peace", "APT38"],
        "ttps": [
            "T1486", "T1059", "T1105", "T1566", "T1078", "T1021",
            "T1036", "T1070", "T1027", "T1071",
        ],
        "motivation": "financial+espionage",
        "origin_country": "North Korea",
        "active": True,
        "associated_campaigns": ["wannacry-2017", "operation-dream-job"],
        "iocs": [
            "175.45.176.0/24", "210.52.109.0/24",
            "lazarus-c2.xyz", "job-opportunity.top",
            "deadbeefdeadbeefdeadbeefdeadbeef",
        ],
    },
    {
        "id": "fin7",
        "name": "FIN7",
        "aliases": ["Carbanak", "Navigator Group", "ITG14"],
        "ttps": [
            "T1566", "T1059", "T1055", "T1036", "T1486", "T1078",
            "T1021", "T1070", "T1027", "T1190",
        ],
        "motivation": "financial",
        "origin_country": "Russia",
        "active": True,
        "associated_campaigns": ["fin7-restaurant-campaign", "fin7-hospitality-2022"],
        "iocs": [
            "23.83.133.0/24", "194.165.16.0/24",
            "finance-update.net", "secure-payment.cc",
            "cafe0102cafe0102cafe0102cafe0102",
        ],
    },
    {
        "id": "apt28",
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "Strontium"],
        "ttps": [
            "T1566", "T1078", "T1059", "T1190", "T1036", "T1021",
            "T1070", "T1027", "T1550", "T1098",
        ],
        "motivation": "espionage",
        "origin_country": "Russia",
        "active": True,
        "associated_campaigns": ["dnc-hack-2016", "operation-pawn-storm"],
        "iocs": [
            "185.220.101.0/24", "91.108.4.0/24",
            "phishing-gov.com", "microsoft-security.ru",
            "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
        ],
    },
    {
        "id": "revil",
        "name": "REvil",
        "aliases": ["Sodinokibi", "Gold Southfield"],
        "ttps": [
            "T1486", "T1490", "T1489", "T1078", "T1059", "T1021",
            "T1070", "T1027", "T1566", "T1055",
        ],
        "motivation": "financial",
        "origin_country": "Russia",
        "active": False,
        "associated_campaigns": ["kaseya-2021", "jbs-foods-2021"],
        "iocs": [
            "5.188.62.0/24", "193.106.31.0/24",
            "decryptor.top", "ransom-pay.su",
            "badf00dbadf00dbadf00dbadf00dbadf",
        ],
    },
    {
        "id": "cozy-bear-cloud",
        "name": "Midnight Blizzard",
        "aliases": ["NOBELIUM", "NobleBaron"],
        "ttps": [
            "T1566", "T1078", "T1098", "T1550", "T1021", "T1059",
            "T1190", "T1070", "T1105", "T1036",
        ],
        "motivation": "espionage",
        "origin_country": "Russia",
        "active": True,
        "associated_campaigns": ["solarwinds-2020", "teams-phishing-2023"],
        "iocs": [
            "40.126.0.0/16", "52.167.144.0/24",
            "o365-login.com", "teams-update.net",
            "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d",
        ],
    },
    {
        "id": "darkside",
        "name": "DarkSide",
        "aliases": ["Carbon Spider", "Blackmatter"],
        "ttps": [
            "T1486", "T1490", "T1078", "T1059", "T1021", "T1070",
            "T1027", "T1489", "T1055", "T1566",
        ],
        "motivation": "financial",
        "origin_country": "Russia",
        "active": False,
        "associated_campaigns": ["colonial-pipeline-2021"],
        "iocs": [
            "198.199.0.0/16", "167.172.0.0/16",
            "darkside-leaks.com", "ransom-darkside.onion",
            "5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b",
        ],
    },
    {
        "id": "apt10",
        "name": "APT10",
        "aliases": ["Stone Panda", "MenuPass", "Cloud Hopper"],
        "ttps": [
            "T1078", "T1021", "T1059", "T1036", "T1070", "T1105",
            "T1027", "T1566", "T1190", "T1055",
        ],
        "motivation": "espionage",
        "origin_country": "China",
        "active": True,
        "associated_campaigns": ["cloud-hopper-2017", "apt10-msp-campaign"],
        "iocs": [
            "103.224.80.0/24", "45.32.22.0/24",
            "cloud-backup.jp", "managed-services.cc",
            "3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f",
        ],
    },
    {
        "id": "lapsus",
        "name": "LAPSUS$",
        "aliases": ["DEV-0537", "Strawberry Tempest"],
        "ttps": [
            "T1078", "T1566", "T1098", "T1550", "T1059", "T1036",
            "T1070", "T1190", "T1021", "T1531",
        ],
        "motivation": "financial+notoriety",
        "origin_country": "UK/Brazil",
        "active": True,
        "associated_campaigns": ["okta-breach-2022", "nvidia-breach-2022"],
        "iocs": [
            "185.193.126.0/24", "109.205.213.0/24",
            "lapsus-leak.com", "data-breach.top",
            "4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a",
        ],
    },
]

_BUILTIN_CAMPAIGNS: List[Dict[str, Any]] = [
    {
        "id": "solarwinds-2020",
        "name": "SolarWinds SUNBURST",
        "threat_actor_id": "apt29",
        "start_date": "2020-03-01T00:00:00+00:00",
        "status": "concluded",
        "targets": ["government", "defense", "technology", "critical-infrastructure"],
        "iocs": ["avsvmcloud.com", "databasegalore.com", "freescanonline.com"],
        "ttps": ["T1195", "T1078", "T1070", "T1036", "T1059"],
    },
    {
        "id": "colonial-pipeline-2021",
        "name": "Colonial Pipeline Ransomware",
        "threat_actor_id": "darkside",
        "start_date": "2021-05-07T00:00:00+00:00",
        "status": "concluded",
        "targets": ["energy", "critical-infrastructure", "oil-gas"],
        "iocs": ["198.199.67.0/24", "darkside-decryption.com"],
        "ttps": ["T1486", "T1490", "T1078", "T1021"],
    },
    {
        "id": "kaseya-2021",
        "name": "Kaseya VSA Supply Chain Attack",
        "threat_actor_id": "revil",
        "start_date": "2021-07-02T00:00:00+00:00",
        "status": "concluded",
        "targets": ["msp", "technology", "small-business"],
        "iocs": ["agent.crt", "kaseya-decryptor.top"],
        "ttps": ["T1195", "T1486", "T1490", "T1059"],
    },
    {
        "id": "operation-dream-job",
        "name": "Operation Dream Job",
        "threat_actor_id": "lazarus",
        "start_date": "2020-08-01T00:00:00+00:00",
        "status": "active",
        "targets": ["defense", "aerospace", "financial", "cryptocurrency"],
        "iocs": ["job-opportunity.top", "aerospace-careers.com"],
        "ttps": ["T1566", "T1059", "T1105", "T1078"],
    },
    {
        "id": "okta-breach-2022",
        "name": "Okta Identity Provider Breach",
        "threat_actor_id": "lapsus",
        "start_date": "2022-01-16T00:00:00+00:00",
        "status": "concluded",
        "targets": ["technology", "identity-provider", "saas"],
        "iocs": ["185.193.126.0/24", "lapsus-leak.com"],
        "ttps": ["T1078", "T1550", "T1098", "T1531"],
    },
]


# ============================================================================
# CORRELATOR ENGINE
# ============================================================================


class ThreatIntelCorrelator:
    """
    SQLite-backed threat intelligence correlation engine.

    Matches security findings against known threat actor profiles and campaigns
    using IOC and TTP overlap scoring to produce confidence-weighted correlations.

    Thread-safe via RLock. For in-memory databases (":memory:") a single
    persistent connection is kept open so that the schema survives across
    multiple method calls; for file-based databases a new connection is opened
    per operation (standard SQLite usage).
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        """
        Initialize correlator.

        Args:
            db_path: SQLite database path. Use ":memory:" for tests.
        """
        self.db_path = db_path
        self._lock = threading.RLock()
        # For :memory: DBs keep one persistent connection so the schema is shared.
        self._memory_conn: Optional[sqlite3.Connection] = None
        if db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._init_db()
        self._seed_builtin_data()

    def _connect(self) -> sqlite3.Connection:
        """Return the appropriate connection (shared for :memory:, new for file)."""
        if self._memory_conn is not None:
            return self._memory_conn
        return self._connect()

    def _close(self, conn: sqlite3.Connection) -> None:
        """Close connection only if it is not the shared in-memory connection."""
        if conn is not self._memory_conn:
            self._close(conn)

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create SQLite schema."""
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS threat_actors (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        aliases TEXT DEFAULT '[]',
                        ttps TEXT DEFAULT '[]',
                        motivation TEXT DEFAULT 'unknown',
                        origin_country TEXT,
                        active INTEGER DEFAULT 1,
                        associated_campaigns TEXT DEFAULT '[]',
                        iocs TEXT DEFAULT '[]',
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS campaigns (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        threat_actor_id TEXT NOT NULL,
                        start_date TEXT,
                        status TEXT DEFAULT 'active',
                        targets TEXT DEFAULT '[]',
                        iocs TEXT DEFAULT '[]',
                        ttps TEXT DEFAULT '[]',
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (threat_actor_id) REFERENCES threat_actors(id)
                    );

                    CREATE TABLE IF NOT EXISTS correlations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        finding_id TEXT NOT NULL,
                        threat_actor_id TEXT,
                        campaign_id TEXT,
                        confidence REAL DEFAULT 0.0,
                        ioc_matches TEXT DEFAULT '[]',
                        ttp_matches TEXT DEFAULT '[]',
                        correlated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE INDEX IF NOT EXISTS idx_actors_active
                        ON threat_actors (active);
                    CREATE INDEX IF NOT EXISTS idx_campaigns_actor
                        ON campaigns (threat_actor_id);
                    CREATE INDEX IF NOT EXISTS idx_correlations_finding
                        ON correlations (finding_id);
                    """
                )
                conn.commit()
            finally:
                self._close(conn)

    def _seed_builtin_data(self) -> None:
        """Seed built-in APT profiles and campaigns (idempotent)."""
        for actor_data in _BUILTIN_ACTORS:
            try:
                self.add_threat_actor(ThreatActor(**actor_data))
            except Exception:
                pass  # Already exists — skip silently

        for campaign_data in _BUILTIN_CAMPAIGNS:
            try:
                self.add_campaign(Campaign(**campaign_data))
            except Exception:
                pass  # Already exists — skip silently

    # ------------------------------------------------------------------
    # WRITE OPERATIONS
    # ------------------------------------------------------------------

    def add_threat_actor(self, actor: ThreatActor) -> str:
        """
        Register a threat actor profile.

        Args:
            actor: ThreatActor model instance

        Returns:
            Actor ID
        """
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO threat_actors
                    (id, name, aliases, ttps, motivation, origin_country,
                     active, associated_campaigns, iocs)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        actor.id,
                        actor.name,
                        json.dumps(actor.aliases),
                        json.dumps(actor.ttps),
                        actor.motivation,
                        actor.origin_country,
                        1 if actor.active else 0,
                        json.dumps(actor.associated_campaigns),
                        json.dumps(actor.iocs),
                    ),
                )
                conn.commit()
                _logger.debug("Registered threat actor: %s (%s)", actor.name, actor.id)
                return actor.id
            finally:
                self._close(conn)

    def add_campaign(self, campaign: Campaign) -> str:
        """
        Register a threat campaign.

        Args:
            campaign: Campaign model instance

        Returns:
            Campaign ID
        """
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO campaigns
                    (id, name, threat_actor_id, start_date, status,
                     targets, iocs, ttps)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        campaign.id,
                        campaign.name,
                        campaign.threat_actor_id,
                        campaign.start_date,
                        campaign.status,
                        json.dumps(campaign.targets),
                        json.dumps(campaign.iocs),
                        json.dumps(campaign.ttps),
                    ),
                )
                conn.commit()
                _logger.debug("Registered campaign: %s (%s)", campaign.name, campaign.id)
                return campaign.id
            finally:
                self._close(conn)

    # ------------------------------------------------------------------
    # CORRELATION LOGIC
    # ------------------------------------------------------------------

    def _compute_confidence(
        self,
        ioc_matches: List[str],
        ttp_matches: List[str],
        actor_ioc_count: int,
        actor_ttp_count: int,
    ) -> float:
        """
        Compute a confidence score from IOC and TTP match ratios.

        IOC matches contribute 60%, TTP matches 40%.
        Returns a value in [0.0, 1.0].
        """
        ioc_ratio = len(ioc_matches) / max(actor_ioc_count, 1)
        ttp_ratio = len(ttp_matches) / max(actor_ttp_count, 1)
        raw = (0.6 * min(ioc_ratio, 1.0)) + (0.4 * min(ttp_ratio, 1.0))
        # Boost: any single IOC match gives at least 0.30 confidence
        if ioc_matches:
            raw = max(raw, 0.30)
        # Boost: any single TTP match gives at least 0.15 confidence
        elif ttp_matches:
            raw = max(raw, 0.15)
        return round(min(raw, 1.0), 4)

    def _load_all_actors(self) -> List[ThreatActor]:
        """Load all actors from DB."""
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute("SELECT * FROM threat_actors")
                rows = cur.fetchall()
                cols = [d[0] for d in cur.description]
                actors = []
                for row in rows:
                    d = dict(zip(cols, row))
                    actors.append(
                        ThreatActor(
                            id=d["id"],
                            name=d["name"],
                            aliases=json.loads(d["aliases"]),
                            ttps=json.loads(d["ttps"]),
                            motivation=d["motivation"],
                            origin_country=d["origin_country"],
                            active=bool(d["active"]),
                            associated_campaigns=json.loads(d["associated_campaigns"]),
                            iocs=json.loads(d["iocs"]),
                        )
                    )
                return actors
            finally:
                self._close(conn)

    def _load_campaigns_for_actor(self, actor_id: str) -> List[Campaign]:
        """Load campaigns for a specific actor."""
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT * FROM campaigns WHERE threat_actor_id = ?", (actor_id,)
                )
                rows = cur.fetchall()
                cols = [d[0] for d in cur.description]
                campaigns = []
                for row in rows:
                    d = dict(zip(cols, row))
                    campaigns.append(
                        Campaign(
                            id=d["id"],
                            name=d["name"],
                            threat_actor_id=d["threat_actor_id"],
                            start_date=d["start_date"] or "",
                            status=d["status"],
                            targets=json.loads(d["targets"]),
                            iocs=json.loads(d["iocs"]),
                            ttps=json.loads(d["ttps"]),
                        )
                    )
                return campaigns
            finally:
                self._close(conn)

    def _finding_to_indicators(self, finding: Dict[str, Any]) -> tuple[List[str], List[str]]:
        """
        Extract IOCs and TTPs from a finding dict.

        Finding may have keys: iocs, ttps, indicators, techniques, cve, host, ip, domain.
        Returns (iocs, ttps).
        """
        iocs: List[str] = []
        ttps: List[str] = []

        # Direct IOC fields
        for key in ("iocs", "indicators", "indicators_of_compromise"):
            if isinstance(finding.get(key), list):
                iocs.extend(str(v) for v in finding[key])

        # IP / domain / hash fields
        for key in ("ip", "host", "domain", "hash", "file_hash", "src_ip", "dst_ip"):
            if finding.get(key):
                iocs.append(str(finding[key]))

        # CVE → IOC
        if finding.get("cve"):
            iocs.append(str(finding["cve"]))

        # TTP / MITRE fields
        for key in ("ttps", "techniques", "mitre_techniques", "attack_techniques"):
            if isinstance(finding.get(key), list):
                ttps.extend(str(v) for v in finding[key])

        # Single technique field
        if finding.get("technique"):
            ttps.append(str(finding["technique"]))

        # Deduplicate preserving order
        seen: set = set()
        iocs_dedup: List[str] = []
        for v in iocs:
            if v not in seen:
                seen.add(v)
                iocs_dedup.append(v)

        seen = set()
        ttps_dedup: List[str] = []
        for v in ttps:
            if v not in seen:
                seen.add(v)
                ttps_dedup.append(v)

        return iocs_dedup, ttps_dedup

    def correlate_finding(self, finding: Dict[str, Any]) -> ThreatCorrelation:
        """
        Match a finding against all known threat actors and campaigns.

        The actor/campaign with the highest confidence score wins. If no match
        meets a minimum threshold (0.05), returns a zero-confidence correlation.

        Args:
            finding: Dict with at least "id" key, plus IOC/TTP fields.

        Returns:
            ThreatCorrelation with best match
        """
        finding_id = str(finding.get("id", str(uuid.uuid4())))
        finding_iocs, finding_ttps = self._finding_to_indicators(finding)

        best_correlation = ThreatCorrelation(finding_id=finding_id)
        best_confidence = 0.0

        actors = self._load_all_actors()
        for actor in actors:
            actor_iocs_set = set(actor.iocs)
            actor_ttps_set = set(actor.ttps)

            ioc_matches = [ioc for ioc in finding_iocs if ioc in actor_iocs_set]
            ttp_matches = [ttp for ttp in finding_ttps if ttp in actor_ttps_set]

            if not ioc_matches and not ttp_matches:
                continue

            confidence = self._compute_confidence(
                ioc_matches, ttp_matches, len(actor.iocs), len(actor.ttps)
            )

            if confidence <= best_confidence:
                continue

            # Find best campaign for this actor
            best_campaign: Optional[Campaign] = None
            best_campaign_confidence = 0.0
            for campaign in self._load_campaigns_for_actor(actor.id):
                camp_ioc_matches = [i for i in finding_iocs if i in set(campaign.iocs)]
                camp_ttp_matches = [t for t in finding_ttps if t in set(campaign.ttps)]
                camp_conf = self._compute_confidence(
                    camp_ioc_matches, camp_ttp_matches,
                    len(campaign.iocs) or 1, len(campaign.ttps) or 1,
                )
                if camp_conf > best_campaign_confidence:
                    best_campaign_confidence = camp_conf
                    best_campaign = campaign

            best_confidence = confidence
            best_correlation = ThreatCorrelation(
                finding_id=finding_id,
                threat_actor=actor,
                campaign=best_campaign,
                confidence=confidence,
                ioc_matches=ioc_matches,
                ttp_matches=ttp_matches,
            )

        # Persist correlation
        if best_confidence > 0:
            self._persist_correlation(best_correlation)

        return best_correlation

    def correlate_batch(self, findings: List[Dict[str, Any]]) -> List[ThreatCorrelation]:
        """
        Correlate multiple findings in sequence.

        Args:
            findings: List of finding dicts

        Returns:
            List of ThreatCorrelation results (same order as input)
        """
        return [self.correlate_finding(f) for f in findings]

    def _persist_correlation(self, correlation: ThreatCorrelation) -> None:
        """Store correlation result in DB."""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO correlations
                    (finding_id, threat_actor_id, campaign_id, confidence,
                     ioc_matches, ttp_matches, correlated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        correlation.finding_id,
                        correlation.threat_actor.id if correlation.threat_actor else None,
                        correlation.campaign.id if correlation.campaign else None,
                        correlation.confidence,
                        json.dumps(correlation.ioc_matches),
                        json.dumps(correlation.ttp_matches),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
            finally:
                self._close(conn)

    # ------------------------------------------------------------------
    # READ OPERATIONS
    # ------------------------------------------------------------------

    def get_active_threats(self, org_id: str) -> List[ThreatActor]:
        """
        Return all currently active threat actors relevant to an org.

        Currently returns all active actors; can be extended with org-specific
        sector targeting logic.

        Args:
            org_id: Organisation identifier

        Returns:
            List of active ThreatActor profiles
        """
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT * FROM threat_actors WHERE active = 1 ORDER BY name"
                )
                rows = cur.fetchall()
                cols = [d[0] for d in cur.description]
                result = []
                for row in rows:
                    d = dict(zip(cols, row))
                    result.append(
                        ThreatActor(
                            id=d["id"],
                            name=d["name"],
                            aliases=json.loads(d["aliases"]),
                            ttps=json.loads(d["ttps"]),
                            motivation=d["motivation"],
                            origin_country=d["origin_country"],
                            active=bool(d["active"]),
                            associated_campaigns=json.loads(d["associated_campaigns"]),
                            iocs=json.loads(d["iocs"]),
                        )
                    )
                return result
            finally:
                self._close(conn)

    def get_actor_profile(self, actor_id: str) -> Optional[Dict[str, Any]]:
        """
        Return full actor dossier: profile + campaigns + recent correlations.

        Args:
            actor_id: Threat actor ID

        Returns:
            Dict with actor, campaigns, and recent_correlations keys, or None
        """
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.cursor()

                # Actor
                cur.execute(
                    "SELECT * FROM threat_actors WHERE id = ?", (actor_id,)
                )
                row = cur.fetchone()
                if row is None:
                    return None
                cols = [d[0] for d in cur.description]
                d = dict(zip(cols, row))
                actor = ThreatActor(
                    id=d["id"],
                    name=d["name"],
                    aliases=json.loads(d["aliases"]),
                    ttps=json.loads(d["ttps"]),
                    motivation=d["motivation"],
                    origin_country=d["origin_country"],
                    active=bool(d["active"]),
                    associated_campaigns=json.loads(d["associated_campaigns"]),
                    iocs=json.loads(d["iocs"]),
                )

                # Campaigns
                cur.execute(
                    "SELECT * FROM campaigns WHERE threat_actor_id = ? ORDER BY start_date DESC",
                    (actor_id,),
                )
                camp_rows = cur.fetchall()
                camp_cols = [d[0] for d in cur.description]
                campaigns = []
                for cr in camp_rows:
                    cd = dict(zip(camp_cols, cr))
                    campaigns.append(
                        Campaign(
                            id=cd["id"],
                            name=cd["name"],
                            threat_actor_id=cd["threat_actor_id"],
                            start_date=cd["start_date"] or "",
                            status=cd["status"],
                            targets=json.loads(cd["targets"]),
                            iocs=json.loads(cd["iocs"]),
                            ttps=json.loads(cd["ttps"]),
                        ).model_dump()
                    )

                # Recent correlations
                cur.execute(
                    """
                    SELECT finding_id, confidence, ioc_matches, ttp_matches, correlated_at
                    FROM correlations
                    WHERE threat_actor_id = ?
                    ORDER BY correlated_at DESC
                    LIMIT 20
                    """,
                    (actor_id,),
                )
                corr_rows = cur.fetchall()
                recent_correlations = [
                    {
                        "finding_id": r[0],
                        "confidence": r[1],
                        "ioc_matches": json.loads(r[2]),
                        "ttp_matches": json.loads(r[3]),
                        "correlated_at": r[4],
                    }
                    for r in corr_rows
                ]

                return {
                    "actor": actor.model_dump(),
                    "campaigns": campaigns,
                    "recent_correlations": recent_correlations,
                    "total_correlations": len(recent_correlations),
                }
            finally:
                self._close(conn)

    def get_campaign_timeline(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """
        Return campaign details and associated correlation events as a timeline.

        Args:
            campaign_id: Campaign ID

        Returns:
            Dict with campaign info and timeline events, or None if not found
        """
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.cursor()

                # Campaign
                cur.execute(
                    "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
                )
                row = cur.fetchone()
                if row is None:
                    return None
                cols = [d[0] for d in cur.description]
                d = dict(zip(cols, row))
                campaign = Campaign(
                    id=d["id"],
                    name=d["name"],
                    threat_actor_id=d["threat_actor_id"],
                    start_date=d["start_date"] or "",
                    status=d["status"],
                    targets=json.loads(d["targets"]),
                    iocs=json.loads(d["iocs"]),
                    ttps=json.loads(d["ttps"]),
                )

                # Timeline: correlations attributed to this campaign
                cur.execute(
                    """
                    SELECT finding_id, confidence, ioc_matches, ttp_matches, correlated_at
                    FROM correlations
                    WHERE campaign_id = ?
                    ORDER BY correlated_at ASC
                    """,
                    (campaign_id,),
                )
                events = [
                    {
                        "event_type": "finding_correlated",
                        "finding_id": r[0],
                        "confidence": r[1],
                        "ioc_matches": json.loads(r[2]),
                        "ttp_matches": json.loads(r[3]),
                        "timestamp": r[4],
                    }
                    for r in cur.fetchall()
                ]

                return {
                    "campaign": campaign.model_dump(),
                    "timeline": events,
                    "event_count": len(events),
                }
            finally:
                self._close(conn)

    def get_threat_landscape(self, org_id: str) -> Dict[str, Any]:
        """
        Return a high-level overview of the threat landscape for an org.

        Includes active actors, active campaigns, and top correlated threats.

        Args:
            org_id: Organisation identifier

        Returns:
            Dict with landscape summary
        """
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.cursor()

                # Active actor count
                cur.execute("SELECT COUNT(*) FROM threat_actors WHERE active = 1")
                active_actor_count = cur.fetchone()[0]

                # Active campaign count
                cur.execute("SELECT COUNT(*) FROM campaigns WHERE status = 'active'")
                active_campaign_count = cur.fetchone()[0]

                # Total correlations for this org (all findings)
                cur.execute("SELECT COUNT(*) FROM correlations")
                total_correlations = cur.fetchone()[0]

                # Top 5 most correlated actors
                cur.execute(
                    """
                    SELECT c.threat_actor_id, ta.name, COUNT(*) as hit_count,
                           AVG(c.confidence) as avg_confidence
                    FROM correlations c
                    JOIN threat_actors ta ON c.threat_actor_id = ta.id
                    WHERE c.threat_actor_id IS NOT NULL
                    GROUP BY c.threat_actor_id
                    ORDER BY hit_count DESC
                    LIMIT 5
                    """
                )
                top_actors = [
                    {
                        "actor_id": r[0],
                        "actor_name": r[1],
                        "correlation_count": r[2],
                        "avg_confidence": round(r[3], 4),
                    }
                    for r in cur.fetchall()
                ]

                # Active campaigns list
                cur.execute(
                    """
                    SELECT id, name, threat_actor_id, start_date, status, targets
                    FROM campaigns
                    WHERE status = 'active'
                    ORDER BY start_date DESC
                    """
                )
                active_campaigns = [
                    {
                        "campaign_id": r[0],
                        "name": r[1],
                        "threat_actor_id": r[2],
                        "start_date": r[3],
                        "status": r[4],
                        "targets": json.loads(r[5]),
                    }
                    for r in cur.fetchall()
                ]

                return {
                    "org_id": org_id,
                    "active_threat_actors": active_actor_count,
                    "active_campaigns": active_campaign_count,
                    "total_correlations": total_correlations,
                    "top_correlated_actors": top_actors,
                    "active_campaign_list": active_campaigns,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            finally:
                self._close(conn)
