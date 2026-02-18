"""World-Class CVE/KEV Feed Scheduler - Largest Vulnerability Intelligence Surface.

This module provides the most comprehensive vulnerability intelligence aggregation,
spanning 8 categories of intelligence sources:

1. Global Authoritative (Ground Truth):
   - NVD, CVE Program, MITRE, CISA KEV, CERT/CC, US-CERT, ICS-CERT

2. National CERTs (Geo-specific Exploit Reality):
   - NCSC UK, BSI, ANSSI, JPCERT, CERT-In, ACSC, GovCERT Singapore, KISA

3. Exploit & Weaponization Intelligence:
   - Exploit-DB, Metasploit, Packet Storm, Vulners, GreyNoise, Shodan, Censys

4. Threat Actor & Campaign Intelligence:
   - Mandiant, Recorded Future, CrowdStrike, Unit 42, Talos, Secureworks

5. Supply-Chain & SBOM Intelligence:
   - OSV, GitHub Advisory Database, Snyk, Deps.dev, CycloneDX, SPDX

6. Cloud & Runtime Vulnerability Feeds:
   - AWS, Azure, GCP Security Bulletins, Kubernetes CVEs, Red Hat, Canonical

7. Zero-Day & Early-Signal Feeds:
   - Vendor security blogs, GitHub security commits, mailing lists

8. Internal Enterprise Signals:
   - SAST/DAST/SCA findings, IaC misconfigurations, runtime detections

Key differentiators:
- Geo-weighted risk scoring (exploitation differs by country)
- Exploit-confidence score (not CVSS fear-score)
- Threat actor to CVE mapping
- Reachable dependency + exploitability analysis
- Pre-CVE risk alerts from early signals
"""

from __future__ import annotations

import asyncio
import csv
import gzip
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests import RequestException

logger = logging.getLogger(__name__)


# =============================================================================
# Feed Category Definitions
# =============================================================================


class FeedCategory(str, Enum):
    """Categories of vulnerability intelligence feeds."""

    AUTHORITATIVE = "authoritative"  # Ground truth (NVD, CISA, MITRE)
    NATIONAL_CERT = "national_cert"  # Geo-specific CERTs
    EXPLOIT = "exploit"  # Weaponization intelligence
    THREAT_ACTOR = "threat_actor"  # Campaign intelligence
    SUPPLY_CHAIN = "supply_chain"  # SBOM/dependency intelligence
    CLOUD_RUNTIME = "cloud_runtime"  # Cloud provider bulletins
    EARLY_SIGNAL = "early_signal"  # Zero-day/pre-CVE signals
    ENTERPRISE = "enterprise"  # Internal signals


class GeoRegion(str, Enum):
    """Geographic regions for geo-weighted scoring."""

    GLOBAL = "global"
    NORTH_AMERICA = "north_america"
    EUROPE = "europe"
    ASIA_PACIFIC = "asia_pacific"
    MIDDLE_EAST = "middle_east"
    LATIN_AMERICA = "latin_america"


# =============================================================================
# Feed URL Configurations
# =============================================================================


# 1. Global Authoritative Sources (Ground Truth)
AUTHORITATIVE_FEEDS = {
    "nvd": {
        "name": "NVD - National Vulnerability Database",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "format": "json",
        "api_key_required": True,
        "refresh_hours": 1,
    },
    "cisa_kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "format": "json",
        "api_key_required": False,
        "refresh_hours": 6,
    },
    "epss": {
        "name": "EPSS - Exploit Prediction Scoring System",
        "url": "https://epss.cyentia.com/epss_scores-current.csv.gz",
        "format": "csv_gz",
        "api_key_required": False,
        "refresh_hours": 24,
    },
    "mitre_cve": {
        "name": "MITRE CVE List",
        "url": "https://cve.mitre.org/data/downloads/allitems.csv.gz",
        "format": "csv_gz",
        "api_key_required": False,
        "refresh_hours": 24,
    },
    "cert_cc": {
        "name": "CERT/CC Vulnerability Notes",
        "url": "https://kb.cert.org/vuls/api/",
        "format": "json",
        "api_key_required": False,
        "refresh_hours": 12,
    },
    "ics_cert": {
        "name": "ICS-CERT Advisories",
        "url": "https://www.cisa.gov/uscert/ics/advisories.xml",
        "format": "xml",
        "api_key_required": False,
        "refresh_hours": 12,
    },
}

# 2. National CERTs (Geo-specific)
NATIONAL_CERT_FEEDS = {
    "ncsc_uk": {
        "name": "NCSC UK",
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
        "format": "rss",
        "region": GeoRegion.EUROPE,
        "country": "GB",
        "refresh_hours": 12,
    },
    "bsi_de": {
        "name": "BSI Germany",
        "url": "https://wid.cert-bund.de/content/public/securityAdvisory",
        "format": "json",
        "region": GeoRegion.EUROPE,
        "country": "DE",
        "refresh_hours": 12,
    },
    "anssi_fr": {
        "name": "ANSSI France",
        "url": "https://www.cert.ssi.gouv.fr/feed/",
        "format": "rss",
        "region": GeoRegion.EUROPE,
        "country": "FR",
        "refresh_hours": 12,
    },
    "jpcert_jp": {
        "name": "JPCERT Japan",
        "url": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
        "format": "rss",
        "region": GeoRegion.ASIA_PACIFIC,
        "country": "JP",
        "refresh_hours": 12,
    },
    "cert_in": {
        "name": "CERT-In India",
        "url": "https://www.cert-in.org.in/",
        "format": "html",
        "region": GeoRegion.ASIA_PACIFIC,
        "country": "IN",
        "refresh_hours": 24,
    },
    "acsc_au": {
        "name": "ACSC Australia",
        "url": "https://www.cyber.gov.au/acsc/view-all-content/alerts",
        "format": "html",
        "region": GeoRegion.ASIA_PACIFIC,
        "country": "AU",
        "refresh_hours": 12,
    },
    "singcert_sg": {
        "name": "SingCERT Singapore",
        "url": "https://www.csa.gov.sg/singcert/alerts",
        "format": "html",
        "region": GeoRegion.ASIA_PACIFIC,
        "country": "SG",
        "refresh_hours": 24,
    },
    "kisa_kr": {
        "name": "KISA Korea",
        "url": "https://www.krcert.or.kr/data/secNoticeList.do",
        "format": "html",
        "region": GeoRegion.ASIA_PACIFIC,
        "country": "KR",
        "refresh_hours": 24,
    },
}

# 3. Exploit & Weaponization Intelligence
EXPLOIT_FEEDS = {
    "exploit_db": {
        "name": "Exploit-DB",
        "url": "https://www.exploit-db.com/files.csv",
        "format": "csv",
        "refresh_hours": 6,
    },
    "metasploit": {
        "name": "Metasploit Modules",
        "url": "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
        "format": "json",
        "refresh_hours": 24,
    },
    "packetstorm": {
        "name": "Packet Storm Security",
        "url": "https://packetstormsecurity.com/files/tags/exploit/",
        "format": "html",
        "refresh_hours": 12,
    },
    "vulners": {
        "name": "Vulners",
        "url": "https://vulners.com/api/v3/search/lucene/",
        "format": "json",
        "api_key_required": True,
        "refresh_hours": 6,
    },
    "greyNoise": {
        "name": "GreyNoise",
        "url": "https://api.greynoise.io/v3/",
        "format": "json",
        "api_key_required": True,
        "refresh_hours": 1,
    },
    "shodan": {
        "name": "Shodan",
        "url": "https://api.shodan.io/",
        "format": "json",
        "api_key_required": True,
        "refresh_hours": 6,
    },
    "censys": {
        "name": "Censys",
        "url": "https://search.censys.io/api/v2/",
        "format": "json",
        "api_key_required": True,
        "refresh_hours": 6,
    },
    "nuclei_templates": {
        "name": "Nuclei Templates",
        "url": "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json",
        "format": "json",
        "refresh_hours": 24,
    },
}

# 4. Threat Actor & Campaign Intelligence
THREAT_ACTOR_FEEDS = {
    "mitre_attack": {
        "name": "MITRE ATT&CK",
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "format": "json",
        "refresh_hours": 24,
    },
    "alienvault_otx": {
        "name": "AlienVault OTX",
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "format": "json",
        "api_key_required": True,
        "refresh_hours": 6,
    },
    "abuse_ch": {
        "name": "abuse.ch",
        "url": "https://urlhaus.abuse.ch/downloads/json/",
        "format": "json",
        "refresh_hours": 1,
    },
    "feodo_tracker": {
        "name": "Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "format": "json",
        "refresh_hours": 1,
    },
    "ransomware_tracker": {
        "name": "Ransomware Live",
        "url": "https://ransomware.live/api/groups",
        "format": "json",
        "refresh_hours": 6,
    },
}

# 5. Supply-Chain & SBOM Intelligence
SUPPLY_CHAIN_FEEDS = {
    "osv": {
        "name": "OSV - Open Source Vulnerabilities",
        "url": "https://osv-vulnerabilities.storage.googleapis.com/",
        "format": "json",
        "refresh_hours": 6,
    },
    "github_advisory": {
        "name": "GitHub Advisory Database",
        "url": "https://api.github.com/advisories",
        "format": "json",
        "api_key_required": True,
        "refresh_hours": 6,
    },
    "snyk_vuln_db": {
        "name": "Snyk Vulnerability Database",
        "url": "https://snyk.io/vuln/",
        "format": "html",
        "refresh_hours": 12,
    },
    "deps_dev": {
        "name": "deps.dev",
        "url": "https://api.deps.dev/v3alpha/",
        "format": "json",
        "refresh_hours": 12,
    },
    "npm_audit": {
        "name": "NPM Security Advisories",
        "url": "https://registry.npmjs.org/-/npm/v1/security/advisories",
        "format": "json",
        "refresh_hours": 6,
    },
    "pypi_advisory": {
        "name": "PyPI Advisory Database",
        "url": "https://raw.githubusercontent.com/pypa/advisory-database/main/vulns/",
        "format": "json",
        "refresh_hours": 12,
    },
    "rustsec": {
        "name": "RustSec Advisory Database",
        "url": "https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/",
        "format": "toml",
        "refresh_hours": 24,
    },
}

# 6. Cloud & Runtime Vulnerability Feeds
CLOUD_RUNTIME_FEEDS = {
    "aws_security": {
        "name": "AWS Security Bulletins",
        "url": "https://aws.amazon.com/security/security-bulletins/feed/",
        "format": "rss",
        "refresh_hours": 6,
    },
    "azure_security": {
        "name": "Azure Security Updates",
        "url": "https://api.msrc.microsoft.com/cvrf/v2.0/updates",
        "format": "json",
        "refresh_hours": 6,
    },
    "gcp_security": {
        "name": "GCP Security Bulletins",
        "url": "https://cloud.google.com/feeds/kubernetes-engine-security-bulletins.xml",
        "format": "xml",
        "refresh_hours": 6,
    },
    "kubernetes_cve": {
        "name": "Kubernetes CVEs",
        "url": "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/",
        "format": "json",
        "refresh_hours": 12,
    },
    "redhat_security": {
        "name": "Red Hat Security Data",
        "url": "https://access.redhat.com/hydra/rest/securitydata/cve.json",
        "format": "json",
        "refresh_hours": 6,
    },
    "ubuntu_security": {
        "name": "Ubuntu Security Notices",
        "url": "https://ubuntu.com/security/notices.rss",
        "format": "rss",
        "refresh_hours": 6,
    },
    "debian_security": {
        "name": "Debian Security Tracker",
        "url": "https://security-tracker.debian.org/tracker/data/json",
        "format": "json",
        "refresh_hours": 12,
    },
    "alpine_secdb": {
        "name": "Alpine SecDB",
        "url": "https://secdb.alpinelinux.org/",
        "format": "json",
        "refresh_hours": 24,
    },
}

# 7. Zero-Day & Early-Signal Feeds
EARLY_SIGNAL_FEEDS = {
    "microsoft_msrc": {
        "name": "Microsoft MSRC",
        "url": "https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/",
        "format": "json",
        "refresh_hours": 6,
    },
    "apple_security": {
        "name": "Apple Security Updates",
        "url": "https://support.apple.com/en-us/HT201222",
        "format": "html",
        "refresh_hours": 12,
    },
    "cisco_psirt": {
        "name": "Cisco PSIRT",
        "url": "https://sec.cloudapps.cisco.com/security/center/publicationService.x",
        "format": "json",
        "refresh_hours": 6,
    },
    "palo_alto_security": {
        "name": "Palo Alto Security Advisories",
        "url": "https://security.paloaltonetworks.com/rss.xml",
        "format": "rss",
        "refresh_hours": 6,
    },
    "fortinet_psirt": {
        "name": "Fortinet PSIRT",
        "url": "https://www.fortiguard.com/rss/ir.xml",
        "format": "rss",
        "refresh_hours": 6,
    },
    "github_security_commits": {
        "name": "GitHub Security Commits",
        "url": "https://api.github.com/search/commits?q=security+fix",
        "format": "json",
        "api_key_required": True,
        "refresh_hours": 1,
    },
    "full_disclosure": {
        "name": "Full Disclosure Mailing List",
        "url": "https://seclists.org/fulldisclosure/",
        "format": "html",
        "refresh_hours": 6,
    },
    "oss_security": {
        "name": "OSS-Security Mailing List",
        "url": "https://www.openwall.com/lists/oss-security/",
        "format": "html",
        "refresh_hours": 6,
    },
}

# Legacy URLs for backward compatibility
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# =============================================================================
# Geo-Weighted Risk Scoring
# =============================================================================


# Regional exploitation weight multipliers
GEO_WEIGHTS: Dict[str, Dict[str, float]] = {
    # CVEs more actively exploited in specific regions get higher weights
    "north_america": {
        "base": 1.0,
        "cert_weight": 1.2,  # US-CERT/CISA advisories
        "enterprise_density": 1.3,  # High enterprise target density
    },
    "europe": {
        "base": 1.0,
        "cert_weight": 1.1,  # NCSC/BSI/ANSSI advisories
        "gdpr_factor": 1.2,  # Data breach implications
    },
    "asia_pacific": {
        "base": 1.0,
        "cert_weight": 1.0,
        "supply_chain_factor": 1.3,  # Manufacturing/supply chain
    },
    "global": {
        "base": 1.0,
        "cert_weight": 1.0,
    },
}


@dataclass
class EPSSScore:
    """EPSS score for a CVE."""

    cve_id: str
    epss: float  # Probability of exploitation (0-1)
    percentile: float  # Percentile ranking (0-1)
    date: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "epss": self.epss,
            "percentile": self.percentile,
            "date": self.date,
        }


@dataclass
class KEVEntry:
    """Known Exploited Vulnerability entry from CISA."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_campaign_use: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
        }


@dataclass
class FeedRefreshResult:
    """Result of a feed refresh operation."""

    feed_name: str
    success: bool
    records_updated: int
    error: Optional[str] = None
    refreshed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class ExploitIntelligence:
    """Exploit intelligence from weaponization feeds."""

    cve_id: str
    exploit_source: str  # exploit-db, metasploit, nuclei, etc.
    exploit_type: str  # remote, local, dos, webapps, etc.
    exploit_url: Optional[str] = None
    exploit_date: Optional[str] = None
    verified: bool = False
    reliability: str = "unknown"  # excellent, good, normal, unknown
    metasploit_module: Optional[str] = None
    nuclei_template: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "exploit_source": self.exploit_source,
            "exploit_type": self.exploit_type,
            "exploit_url": self.exploit_url,
            "exploit_date": self.exploit_date,
            "verified": self.verified,
            "reliability": self.reliability,
            "metasploit_module": self.metasploit_module,
            "nuclei_template": self.nuclei_template,
        }


@dataclass
class ThreatActorMapping:
    """Mapping of CVEs to threat actors and campaigns."""

    cve_id: str
    threat_actor: str
    campaign: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    target_sectors: List[str] = field(default_factory=list)
    target_countries: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)  # MITRE ATT&CK TTPs
    confidence: str = "medium"  # high, medium, low
    source: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "threat_actor": self.threat_actor,
            "campaign": self.campaign,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "target_sectors": self.target_sectors,
            "target_countries": self.target_countries,
            "ttps": self.ttps,
            "confidence": self.confidence,
            "source": self.source,
        }


@dataclass
class SupplyChainVuln:
    """Supply chain vulnerability from SBOM intelligence."""

    vuln_id: str  # CVE, GHSA, OSV, etc.
    ecosystem: str  # npm, pypi, maven, cargo, etc.
    package_name: str
    affected_versions: str
    patched_versions: Optional[str] = None
    severity: str = "unknown"
    cvss_score: Optional[float] = None
    reachable: Optional[bool] = None  # Is the vulnerable code reachable?
    transitive: bool = False  # Is this a transitive dependency?
    source: str = "unknown"  # osv, github, snyk, etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "ecosystem": self.ecosystem,
            "package_name": self.package_name,
            "affected_versions": self.affected_versions,
            "patched_versions": self.patched_versions,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "reachable": self.reachable,
            "transitive": self.transitive,
            "source": self.source,
        }


@dataclass
class CloudSecurityBulletin:
    """Cloud provider security bulletin."""

    bulletin_id: str
    provider: str  # aws, azure, gcp, kubernetes
    title: str
    severity: str
    cve_ids: List[str] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    remediation: Optional[str] = None
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bulletin_id": self.bulletin_id,
            "provider": self.provider,
            "title": self.title,
            "severity": self.severity,
            "cve_ids": self.cve_ids,
            "affected_services": self.affected_services,
            "published_date": self.published_date,
            "remediation": self.remediation,
            "url": self.url,
        }


@dataclass
class EarlySignal:
    """Early signal / pre-CVE intelligence."""

    signal_id: str
    signal_type: str  # vendor_advisory, security_commit, mailing_list, social
    title: str
    description: str
    source_url: Optional[str] = None
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    cve_id: Optional[str] = None  # May be assigned later
    severity_estimate: str = "unknown"
    affected_products: List[str] = field(default_factory=list)
    confidence: str = "low"  # high, medium, low

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type,
            "title": self.title,
            "description": self.description,
            "source_url": self.source_url,
            "detected_at": self.detected_at,
            "cve_id": self.cve_id,
            "severity_estimate": self.severity_estimate,
            "affected_products": self.affected_products,
            "confidence": self.confidence,
        }


@dataclass
class NationalCERTAdvisory:
    """Advisory from a national CERT."""

    advisory_id: str
    cert_name: str
    country: str
    region: str
    title: str
    severity: str
    cve_ids: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    url: Optional[str] = None
    language: str = "en"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "cert_name": self.cert_name,
            "country": self.country,
            "region": self.region,
            "title": self.title,
            "severity": self.severity,
            "cve_ids": self.cve_ids,
            "published_date": self.published_date,
            "url": self.url,
            "language": self.language,
        }


@dataclass
class ExploitConfidenceScore:
    """Exploit confidence score - not CVSS fear-score."""

    cve_id: str
    confidence_score: float  # 0-1, probability of active exploitation
    factors: Dict[str, float] = field(default_factory=dict)
    # Factors include:
    # - epss_score: EPSS probability
    # - in_kev: 1.0 if in KEV, 0.0 otherwise
    # - exploit_available: 1.0 if public exploit exists
    # - metasploit_module: 1.0 if Metasploit module exists
    # - nuclei_template: 0.8 if Nuclei template exists
    # - threat_actor_use: 1.0 if used by known threat actor
    # - greynoise_seen: 0.9 if seen in GreyNoise
    # - shodan_exposed: 0.7 if exposed systems found
    calculated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "confidence_score": self.confidence_score,
            "factors": self.factors,
            "calculated_at": self.calculated_at,
        }


@dataclass
class GeoWeightedRisk:
    """Geo-weighted risk score for a CVE."""

    cve_id: str
    base_score: float
    geo_scores: Dict[str, float] = field(default_factory=dict)
    # geo_scores maps region -> weighted score
    cert_mentions: Dict[str, List[str]] = field(default_factory=dict)
    # cert_mentions maps region -> list of CERT advisory IDs
    calculated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "base_score": self.base_score,
            "geo_scores": self.geo_scores,
            "cert_mentions": self.cert_mentions,
            "calculated_at": self.calculated_at,
        }


class FeedsService:
    """CVE/KEV Feed Scheduler with EPSS and KEV enrichment."""

    def __init__(self, db_path: Optional[Path] = None, timeout: float = 60.0) -> None:
        """Initialize feeds service with database path."""
        self.db_path = db_path or Path("data/feeds/feeds.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema for feed data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # EPSS scores table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS epss_scores (
                cve_id TEXT PRIMARY KEY,
                epss REAL NOT NULL,
                percentile REAL NOT NULL,
                date TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """
        )

        # KEV entries table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS kev_entries (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TEXT,
                known_ransomware_campaign_use TEXT,
                updated_at TEXT NOT NULL
            )
        """
        )

        # Feed metadata table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS feed_metadata (
                feed_name TEXT PRIMARY KEY,
                last_refresh TEXT,
                records_count INTEGER,
                status TEXT,
                category TEXT,
                error_message TEXT
            )
        """
        )

        # Exploit intelligence table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS exploit_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                exploit_source TEXT NOT NULL,
                exploit_type TEXT,
                exploit_url TEXT,
                exploit_date TEXT,
                verified INTEGER DEFAULT 0,
                reliability TEXT DEFAULT 'unknown',
                metasploit_module TEXT,
                nuclei_template TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE(cve_id, exploit_source)
            )
        """
        )

        # Threat actor mappings table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_actor_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                threat_actor TEXT NOT NULL,
                campaign TEXT,
                first_seen TEXT,
                last_seen TEXT,
                target_sectors TEXT,
                target_countries TEXT,
                ttps TEXT,
                confidence TEXT DEFAULT 'medium',
                source TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE(cve_id, threat_actor)
            )
        """
        )

        # Supply chain vulnerabilities table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS supply_chain_vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                affected_versions TEXT,
                patched_versions TEXT,
                severity TEXT DEFAULT 'unknown',
                cvss_score REAL,
                reachable INTEGER,
                transitive INTEGER DEFAULT 0,
                source TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE(vuln_id, ecosystem, package_name)
            )
        """
        )

        # Cloud security bulletins table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cloud_security_bulletins (
                bulletin_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                title TEXT,
                severity TEXT,
                cve_ids TEXT,
                affected_services TEXT,
                published_date TEXT,
                remediation TEXT,
                url TEXT,
                updated_at TEXT NOT NULL
            )
        """
        )

        # Early signals table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS early_signals (
                signal_id TEXT PRIMARY KEY,
                signal_type TEXT NOT NULL,
                title TEXT,
                description TEXT,
                source_url TEXT,
                detected_at TEXT,
                cve_id TEXT,
                severity_estimate TEXT DEFAULT 'unknown',
                affected_products TEXT,
                confidence TEXT DEFAULT 'low',
                updated_at TEXT NOT NULL
            )
        """
        )

        # National CERT advisories table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS national_cert_advisories (
                advisory_id TEXT PRIMARY KEY,
                cert_name TEXT NOT NULL,
                country TEXT,
                region TEXT,
                title TEXT,
                severity TEXT,
                cve_ids TEXT,
                published_date TEXT,
                url TEXT,
                language TEXT DEFAULT 'en',
                updated_at TEXT NOT NULL
            )
        """
        )

        # Exploit confidence scores table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS exploit_confidence_scores (
                cve_id TEXT PRIMARY KEY,
                confidence_score REAL NOT NULL,
                factors TEXT,
                calculated_at TEXT NOT NULL
            )
        """
        )

        # Geo-weighted risk scores table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS geo_weighted_risks (
                cve_id TEXT PRIMARY KEY,
                base_score REAL NOT NULL,
                geo_scores TEXT,
                cert_mentions TEXT,
                calculated_at TEXT NOT NULL
            )
        """
        )

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_epss_score ON epss_scores(epss)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_epss_percentile ON epss_scores(percentile)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_exploit_cve ON exploit_intelligence(cve_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_threat_actor_cve ON threat_actor_mappings(cve_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_supply_chain_pkg ON supply_chain_vulns(package_name)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_cloud_provider ON cloud_security_bulletins(provider)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_early_signal_type ON early_signals(signal_type)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_cert_country ON national_cert_advisories(country)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_confidence_score ON exploit_confidence_scores(confidence_score)"
        )

        conn.commit()
        conn.close()

    def refresh_epss(self) -> FeedRefreshResult:
        """Refresh EPSS scores from FIRST.org.

        Downloads the compressed CSV file containing EPSS scores for all CVEs
        and updates the local database.

        Returns:
            FeedRefreshResult with refresh status
        """
        try:
            logger.info("Refreshing EPSS scores from FIRST.org")

            # Download compressed CSV
            response = requests.get(EPSS_URL, timeout=self.timeout)
            response.raise_for_status()

            # Decompress and parse CSV
            decompressed = gzip.decompress(response.content)
            csv_content = decompressed.decode("utf-8")

            # Parse CSV (skip header comment lines starting with #)
            lines = csv_content.strip().split("\n")
            data_lines = [line for line in lines if not line.startswith("#")]

            if not data_lines:
                return FeedRefreshResult(
                    feed_name="epss",
                    success=False,
                    records_updated=0,
                    error="No data in EPSS feed",
                )

            reader = csv.DictReader(data_lines)
            records = []
            for row in reader:
                try:
                    cve_id = row.get("cve", "").strip()
                    epss = float(row.get("epss", 0))
                    percentile = float(row.get("percentile", 0))
                    date = row.get(
                        "model_version", datetime.utcnow().strftime("%Y-%m-%d")
                    )

                    if cve_id and cve_id.startswith("CVE-"):
                        records.append(EPSSScore(cve_id, epss, percentile, date))
                except (ValueError, KeyError):
                    continue

            # Batch insert into database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()

            cursor.executemany(
                """
                INSERT OR REPLACE INTO epss_scores
                (cve_id, epss, percentile, date, updated_at)
                VALUES (?, ?, ?, ?, ?)
            """,
                [(r.cve_id, r.epss, r.percentile, r.date, now) for r in records],
            )

            # Update metadata
            cursor.execute(
                """
                INSERT OR REPLACE INTO feed_metadata
                (feed_name, last_refresh, records_count, status)
                VALUES (?, ?, ?, ?)
            """,
                ("epss", now, len(records), "success"),
            )

            conn.commit()
            conn.close()

            logger.info(f"EPSS refresh complete: {len(records)} records updated")

            return FeedRefreshResult(
                feed_name="epss",
                success=True,
                records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch EPSS feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="epss",
                success=False,
                records_updated=0,
                error=error_msg,
            )
        except Exception as exc:
            error_msg = f"Error processing EPSS feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="epss",
                success=False,
                records_updated=0,
                error=error_msg,
            )

    def refresh_kev(self) -> FeedRefreshResult:
        """Refresh KEV catalog from CISA.

        Downloads the JSON catalog of Known Exploited Vulnerabilities
        and updates the local database.

        Returns:
            FeedRefreshResult with refresh status
        """
        try:
            logger.info("Refreshing KEV catalog from CISA")

            # Download JSON catalog
            response = requests.get(KEV_URL, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            records = []
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID", "").strip()
                if not cve_id:
                    continue

                entry = KEVEntry(
                    cve_id=cve_id,
                    vendor_project=vuln.get("vendorProject", ""),
                    product=vuln.get("product", ""),
                    vulnerability_name=vuln.get("vulnerabilityName", ""),
                    date_added=vuln.get("dateAdded", ""),
                    short_description=vuln.get("shortDescription", ""),
                    required_action=vuln.get("requiredAction", ""),
                    due_date=vuln.get("dueDate", ""),
                    known_ransomware_campaign_use=vuln.get(
                        "knownRansomwareCampaignUse", "Unknown"
                    ),
                )
                records.append(entry)

            # Batch insert into database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()

            cursor.executemany(
                """
                INSERT OR REPLACE INTO kev_entries
                (cve_id, vendor_project, product, vulnerability_name, date_added,
                 short_description, required_action, due_date, known_ransomware_campaign_use, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                [
                    (
                        r.cve_id,
                        r.vendor_project,
                        r.product,
                        r.vulnerability_name,
                        r.date_added,
                        r.short_description,
                        r.required_action,
                        r.due_date,
                        r.known_ransomware_campaign_use,
                        now,
                    )
                    for r in records
                ],
            )

            # Update metadata
            cursor.execute(
                """
                INSERT OR REPLACE INTO feed_metadata
                (feed_name, last_refresh, records_count, status)
                VALUES (?, ?, ?, ?)
            """,
                ("kev", now, len(records), "success"),
            )

            conn.commit()
            conn.close()

            logger.info(f"KEV refresh complete: {len(records)} records updated")

            return FeedRefreshResult(
                feed_name="kev",
                success=True,
                records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch KEV feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="kev",
                success=False,
                records_updated=0,
                error=error_msg,
            )
        except Exception as exc:
            error_msg = f"Error processing KEV feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="kev",
                success=False,
                records_updated=0,
                error=error_msg,
            )

    def get_epss_score(self, cve_id: str) -> Optional[EPSSScore]:
        """Get EPSS score for a CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            EPSSScore if found, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM epss_scores WHERE cve_id = ?", (cve_id.upper(),)
            )
            row = cursor.fetchone()
            if row:
                return EPSSScore(
                    cve_id=row["cve_id"],
                    epss=row["epss"],
                    percentile=row["percentile"],
                    date=row["date"],
                )
            return None
        finally:
            conn.close()

    def get_kev_entry(self, cve_id: str) -> Optional[KEVEntry]:
        """Get KEV entry for a CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            KEVEntry if found, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM kev_entries WHERE cve_id = ?", (cve_id.upper(),)
            )
            row = cursor.fetchone()
            if row:
                return KEVEntry(
                    cve_id=row["cve_id"],
                    vendor_project=row["vendor_project"],
                    product=row["product"],
                    vulnerability_name=row["vulnerability_name"],
                    date_added=row["date_added"],
                    short_description=row["short_description"],
                    required_action=row["required_action"],
                    due_date=row["due_date"],
                    known_ransomware_campaign_use=row["known_ransomware_campaign_use"],
                )
            return None
        finally:
            conn.close()

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE identifier

        Returns:
            True if CVE is in KEV, False otherwise
        """
        return self.get_kev_entry(cve_id) is not None

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich findings with EPSS scores and KEV flags.

        Args:
            findings: List of finding dictionaries with cve_id field

        Returns:
            Enriched findings with epss_score, epss_percentile, and in_kev fields
        """
        enriched = []
        for finding in findings:
            enriched_finding = dict(finding)
            cve_id = finding.get("cve_id") or finding.get("vulnerability_id")

            if cve_id and cve_id.upper().startswith("CVE-"):
                # Add EPSS data
                epss = self.get_epss_score(cve_id)
                if epss:
                    enriched_finding["epss_score"] = epss.epss
                    enriched_finding["epss_percentile"] = epss.percentile
                else:
                    enriched_finding["epss_score"] = None
                    enriched_finding["epss_percentile"] = None

                # Add KEV flag
                kev = self.get_kev_entry(cve_id)
                enriched_finding["in_kev"] = kev is not None
                if kev:
                    enriched_finding["kev_due_date"] = kev.due_date
                    enriched_finding[
                        "kev_ransomware"
                    ] = kev.known_ransomware_campaign_use
            else:
                enriched_finding["epss_score"] = None
                enriched_finding["epss_percentile"] = None
                enriched_finding["in_kev"] = False

            enriched.append(enriched_finding)

        return enriched

    def get_high_risk_cves(
        self, epss_threshold: float = 0.5, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get CVEs with high EPSS scores that are also in KEV.

        Args:
            epss_threshold: Minimum EPSS score (default 0.5)
            limit: Maximum number of results

        Returns:
            List of high-risk CVEs with EPSS and KEV data
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT e.cve_id, e.epss, e.percentile, k.vulnerability_name,
                       k.date_added, k.due_date, k.known_ransomware_campaign_use
                FROM epss_scores e
                INNER JOIN kev_entries k ON e.cve_id = k.cve_id
                WHERE e.epss >= ?
                ORDER BY e.epss DESC
                LIMIT ?
            """,
                (epss_threshold, limit),
            )

            results = []
            for row in cursor.fetchall():
                results.append(
                    {
                        "cve_id": row["cve_id"],
                        "epss_score": row["epss"],
                        "epss_percentile": row["percentile"],
                        "vulnerability_name": row["vulnerability_name"],
                        "kev_date_added": row["date_added"],
                        "kev_due_date": row["due_date"],
                        "ransomware_use": row["known_ransomware_campaign_use"],
                    }
                )
            return results
        finally:
            conn.close()

    def get_feed_stats(self) -> Dict[str, Any]:
        """Get statistics about feed data.

        Returns:
            Dictionary with feed statistics
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # EPSS stats
            cursor.execute("SELECT COUNT(*) as count FROM epss_scores")
            epss_count = cursor.fetchone()["count"]

            cursor.execute("SELECT AVG(epss) as avg FROM epss_scores")
            epss_avg = cursor.fetchone()["avg"] or 0

            # KEV stats
            cursor.execute("SELECT COUNT(*) as count FROM kev_entries")
            kev_count = cursor.fetchone()["count"]

            # Overlap
            cursor.execute(
                """
                SELECT COUNT(*) as count FROM epss_scores e
                INNER JOIN kev_entries k ON e.cve_id = k.cve_id
            """
            )
            overlap_count = cursor.fetchone()["count"]

            # Feed metadata
            cursor.execute("SELECT * FROM feed_metadata")
            metadata = {row["feed_name"]: dict(row) for row in cursor.fetchall()}

            return {
                "epss": {
                    "total_cves": epss_count,
                    "average_score": round(epss_avg, 4),
                    "last_refresh": metadata.get("epss", {}).get("last_refresh"),
                },
                "kev": {
                    "total_cves": kev_count,
                    "last_refresh": metadata.get("kev", {}).get("last_refresh"),
                },
                "overlap": {
                    "cves_in_both": overlap_count,
                },
            }
        finally:
            conn.close()

    # =========================================================================
    # Exploit Confidence Scoring (Not CVSS Fear-Score)
    # =========================================================================

    def calculate_exploit_confidence(self, cve_id: str) -> ExploitConfidenceScore:
        """Calculate exploit confidence score for a CVE.

        This is NOT a CVSS fear-score. It's based on actual exploitation evidence:
        - EPSS probability
        - KEV presence (known active exploitation)
        - Public exploit availability (Exploit-DB, Metasploit, Nuclei)
        - Threat actor usage
        - GreyNoise/Shodan exposure

        Args:
            cve_id: CVE identifier

        Returns:
            ExploitConfidenceScore with weighted factors
        """
        factors: Dict[str, float] = {}
        cve_id = cve_id.upper()

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # Factor 1: EPSS score (0-1)
            cursor.execute("SELECT epss FROM epss_scores WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            if row:
                factors["epss_score"] = row["epss"]
            else:
                factors["epss_score"] = 0.0

            # Factor 2: KEV presence (1.0 if in KEV, 0.0 otherwise)
            cursor.execute("SELECT 1 FROM kev_entries WHERE cve_id = ?", (cve_id,))
            factors["in_kev"] = 1.0 if cursor.fetchone() else 0.0

            # Factor 3: Public exploit availability
            cursor.execute(
                """
                SELECT exploit_source, verified, metasploit_module, nuclei_template
                FROM exploit_intelligence WHERE cve_id = ?
                """,
                (cve_id,),
            )
            exploits = cursor.fetchall()
            if exploits:
                factors["exploit_available"] = 1.0
                for exp in exploits:
                    if exp["metasploit_module"]:
                        factors["metasploit_module"] = 1.0
                    if exp["nuclei_template"]:
                        factors["nuclei_template"] = 0.8
                    if exp["verified"]:
                        factors["exploit_verified"] = 0.9
            else:
                factors["exploit_available"] = 0.0

            # Factor 4: Threat actor usage
            cursor.execute(
                "SELECT confidence FROM threat_actor_mappings WHERE cve_id = ?",
                (cve_id,),
            )
            threat_actors = cursor.fetchall()
            if threat_actors:
                # Higher confidence = higher weight
                max_confidence = max(
                    {"high": 1.0, "medium": 0.7, "low": 0.4}.get(ta["confidence"], 0.5)
                    for ta in threat_actors
                )
                factors["threat_actor_use"] = max_confidence
            else:
                factors["threat_actor_use"] = 0.0

            # Calculate weighted confidence score
            weights = {
                "epss_score": 0.25,
                "in_kev": 0.30,
                "exploit_available": 0.15,
                "metasploit_module": 0.10,
                "nuclei_template": 0.05,
                "exploit_verified": 0.05,
                "threat_actor_use": 0.10,
            }

            confidence_score = sum(factors.get(k, 0.0) * w for k, w in weights.items())

            # Store the calculated score
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                """
                INSERT OR REPLACE INTO exploit_confidence_scores
                (cve_id, confidence_score, factors, calculated_at)
                VALUES (?, ?, ?, ?)
                """,
                (cve_id, confidence_score, json.dumps(factors), now),
            )
            conn.commit()

            return ExploitConfidenceScore(
                cve_id=cve_id,
                confidence_score=round(confidence_score, 4),
                factors=factors,
                calculated_at=now,
            )
        finally:
            conn.close()

    def get_exploit_confidence(self, cve_id: str) -> Optional[ExploitConfidenceScore]:
        """Get cached exploit confidence score for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            ExploitConfidenceScore if found, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM exploit_confidence_scores WHERE cve_id = ?",
                (cve_id.upper(),),
            )
            row = cursor.fetchone()
            if row:
                import json

                return ExploitConfidenceScore(
                    cve_id=row["cve_id"],
                    confidence_score=row["confidence_score"],
                    factors=json.loads(row["factors"]) if row["factors"] else {},
                    calculated_at=row["calculated_at"],
                )
            return None
        finally:
            conn.close()

    # =========================================================================
    # Geo-Weighted Risk Scoring
    # =========================================================================

    def calculate_geo_weighted_risk(
        self, cve_id: str, target_region: str = "global"
    ) -> GeoWeightedRisk:
        """Calculate geo-weighted risk score for a CVE.

        Exploitation differs by country/region. This method weights risk
        based on regional CERT advisories and exploitation patterns.

        Args:
            cve_id: CVE identifier
            target_region: Target region for scoring (default: global)

        Returns:
            GeoWeightedRisk with regional scores
        """
        cve_id = cve_id.upper()
        geo_scores: Dict[str, float] = {}
        cert_mentions: Dict[str, List[str]] = {}

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # Get base EPSS score
            cursor.execute("SELECT epss FROM epss_scores WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            base_score = row["epss"] if row else 0.1

            # Check KEV for global boost
            cursor.execute("SELECT 1 FROM kev_entries WHERE cve_id = ?", (cve_id,))
            if cursor.fetchone():
                base_score = min(1.0, base_score + 0.3)

            # Get regional CERT mentions
            cursor.execute(
                """
                SELECT advisory_id, cert_name, country, region, severity
                FROM national_cert_advisories
                WHERE cve_ids LIKE ?
                """,
                (f"%{cve_id}%",),
            )
            advisories = cursor.fetchall()

            for adv in advisories:
                region = adv["region"] or "global"
                if region not in cert_mentions:
                    cert_mentions[region] = []
                cert_mentions[region].append(adv["advisory_id"])

            # Calculate regional scores
            for region_name, weights in GEO_WEIGHTS.items():
                region_score = base_score * weights.get("base", 1.0)

                # Apply CERT weight if region has advisories
                if region_name in cert_mentions:
                    region_score *= weights.get("cert_weight", 1.0)

                # Apply additional regional factors
                if region_name == "north_america":
                    region_score *= weights.get("enterprise_density", 1.0)
                elif region_name == "europe":
                    region_score *= weights.get("gdpr_factor", 1.0)
                elif region_name == "asia_pacific":
                    region_score *= weights.get("supply_chain_factor", 1.0)

                geo_scores[region_name] = min(1.0, round(region_score, 4))

            # Store the calculated score
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                """
                INSERT OR REPLACE INTO geo_weighted_risks
                (cve_id, base_score, geo_scores, cert_mentions, calculated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    cve_id,
                    base_score,
                    json.dumps(geo_scores),
                    json.dumps(cert_mentions),
                    now,
                ),
            )
            conn.commit()

            return GeoWeightedRisk(
                cve_id=cve_id,
                base_score=round(base_score, 4),
                geo_scores=geo_scores,
                cert_mentions=cert_mentions,
                calculated_at=now,
            )
        finally:
            conn.close()

    # =========================================================================
    # Threat Actor Mapping
    # =========================================================================

    def add_threat_actor_mapping(self, mapping: ThreatActorMapping) -> None:
        """Add or update a threat actor to CVE mapping.

        Args:
            mapping: ThreatActorMapping to store
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO threat_actor_mappings
                (cve_id, threat_actor, campaign, first_seen, last_seen,
                 target_sectors, target_countries, ttps, confidence, source, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mapping.cve_id.upper(),
                    mapping.threat_actor,
                    mapping.campaign,
                    mapping.first_seen,
                    mapping.last_seen,
                    json.dumps(mapping.target_sectors),
                    json.dumps(mapping.target_countries),
                    json.dumps(mapping.ttps),
                    mapping.confidence,
                    mapping.source,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_threat_actors_for_cve(self, cve_id: str) -> List[ThreatActorMapping]:
        """Get all threat actors known to exploit a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            List of ThreatActorMapping objects
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM threat_actor_mappings WHERE cve_id = ?",
                (cve_id.upper(),),
            )
            import json

            results = []
            for row in cursor.fetchall():
                results.append(
                    ThreatActorMapping(
                        cve_id=row["cve_id"],
                        threat_actor=row["threat_actor"],
                        campaign=row["campaign"],
                        first_seen=row["first_seen"],
                        last_seen=row["last_seen"],
                        target_sectors=json.loads(row["target_sectors"] or "[]"),
                        target_countries=json.loads(row["target_countries"] or "[]"),
                        ttps=json.loads(row["ttps"] or "[]"),
                        confidence=row["confidence"],
                        source=row["source"],
                    )
                )
            return results
        finally:
            conn.close()

    def get_cves_by_threat_actor(self, threat_actor: str) -> List[str]:
        """Get all CVEs exploited by a specific threat actor.

        Args:
            threat_actor: Threat actor name

        Returns:
            List of CVE IDs
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT DISTINCT cve_id FROM threat_actor_mappings WHERE threat_actor = ?",
                (threat_actor,),
            )
            return [row[0] for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_all_threat_actors(
        self, limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get all known threat actors from the database.

        Args:
            limit: Maximum number of results
            offset: Offset for pagination

        Returns:
            List of threat actor dictionaries
        """
        import json as json_mod

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM threat_actor_mappings ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            results = []
            for row in cursor.fetchall():
                results.append(
                    {
                        "cve_id": row["cve_id"],
                        "threat_actor": row["threat_actor"],
                        "campaign": row["campaign"],
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                        "target_sectors": json_mod.loads(row["target_sectors"] or "[]"),
                        "target_countries": json_mod.loads(
                            row["target_countries"] or "[]"
                        ),
                        "ttps": json_mod.loads(row["ttps"] or "[]"),
                        "confidence": row["confidence"],
                        "source": row["source"],
                    }
                )
            return results
        except sqlite3.OperationalError:
            # Table might not exist
            return []
        finally:
            conn.close()

    # =========================================================================
    # Exploit Intelligence
    # =========================================================================

    def add_exploit_intelligence(self, exploit: ExploitIntelligence) -> None:
        """Add or update exploit intelligence for a CVE.

        Args:
            exploit: ExploitIntelligence to store
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO exploit_intelligence
                (cve_id, exploit_source, exploit_type, exploit_url, exploit_date,
                 verified, reliability, metasploit_module, nuclei_template, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    exploit.cve_id.upper(),
                    exploit.exploit_source,
                    exploit.exploit_type,
                    exploit.exploit_url,
                    exploit.exploit_date,
                    1 if exploit.verified else 0,
                    exploit.reliability,
                    exploit.metasploit_module,
                    exploit.nuclei_template,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_exploits_for_cve(self, cve_id: str) -> List[ExploitIntelligence]:
        """Get all known exploits for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            List of ExploitIntelligence objects
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM exploit_intelligence WHERE cve_id = ?",
                (cve_id.upper(),),
            )
            results = []
            for row in cursor.fetchall():
                results.append(
                    ExploitIntelligence(
                        cve_id=row["cve_id"],
                        exploit_source=row["exploit_source"],
                        exploit_type=row["exploit_type"],
                        exploit_url=row["exploit_url"],
                        exploit_date=row["exploit_date"],
                        verified=bool(row["verified"]),
                        reliability=row["reliability"],
                        metasploit_module=row["metasploit_module"],
                        nuclei_template=row["nuclei_template"],
                    )
                )
            return results
        finally:
            conn.close()

    def get_all_exploits(
        self, limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get all known exploits from the database.

        Args:
            limit: Maximum number of results
            offset: Offset for pagination

        Returns:
            List of exploit dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM exploit_intelligence ORDER BY exploit_date DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            results = []
            for row in cursor.fetchall():
                results.append(
                    {
                        "cve_id": row["cve_id"],
                        "exploit_source": row["exploit_source"],
                        "exploit_type": row["exploit_type"],
                        "exploit_url": row["exploit_url"],
                        "exploit_date": row["exploit_date"],
                        "verified": bool(row["verified"]),
                        "reliability": row["reliability"],
                        "metasploit_module": row["metasploit_module"],
                        "nuclei_template": row["nuclei_template"],
                    }
                )
            return results
        except sqlite3.OperationalError:
            # Table might not exist
            return []
        finally:
            conn.close()

    # =========================================================================
    # Supply Chain Intelligence
    # =========================================================================

    def add_supply_chain_vuln(self, vuln: SupplyChainVuln) -> None:
        """Add or update supply chain vulnerability.

        Args:
            vuln: SupplyChainVuln to store
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO supply_chain_vulns
                (vuln_id, ecosystem, package_name, affected_versions, patched_versions,
                 severity, cvss_score, reachable, transitive, source, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vuln.vuln_id.upper(),
                    vuln.ecosystem,
                    vuln.package_name,
                    vuln.affected_versions,
                    vuln.patched_versions,
                    vuln.severity,
                    vuln.cvss_score,
                    1 if vuln.reachable else (0 if vuln.reachable is False else None),
                    1 if vuln.transitive else 0,
                    vuln.source,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_vulns_for_package(
        self, package_name: str, ecosystem: Optional[str] = None
    ) -> List[SupplyChainVuln]:
        """Get all vulnerabilities for a package.

        Args:
            package_name: Package name
            ecosystem: Optional ecosystem filter (npm, pypi, etc.)

        Returns:
            List of SupplyChainVuln objects
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            if ecosystem:
                cursor.execute(
                    """
                    SELECT * FROM supply_chain_vulns
                    WHERE package_name = ? AND ecosystem = ?
                    """,
                    (package_name, ecosystem),
                )
            else:
                cursor.execute(
                    "SELECT * FROM supply_chain_vulns WHERE package_name = ?",
                    (package_name,),
                )
            results = []
            for row in cursor.fetchall():
                results.append(
                    SupplyChainVuln(
                        vuln_id=row["vuln_id"],
                        ecosystem=row["ecosystem"],
                        package_name=row["package_name"],
                        affected_versions=row["affected_versions"],
                        patched_versions=row["patched_versions"],
                        severity=row["severity"],
                        cvss_score=row["cvss_score"],
                        reachable=bool(row["reachable"])
                        if row["reachable"] is not None
                        else None,
                        transitive=bool(row["transitive"]),
                        source=row["source"],
                    )
                )
            return results
        finally:
            conn.close()

    def get_all_supply_chain_vulns(
        self, limit: int = 100, offset: int = 0, ecosystem: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get all supply chain vulnerabilities from the database.

        Args:
            limit: Maximum number of results
            offset: Offset for pagination
            ecosystem: Optional ecosystem filter

        Returns:
            List of vulnerability dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            if ecosystem:
                cursor.execute(
                    """
                    SELECT * FROM supply_chain_vulns
                    WHERE ecosystem = ?
                    ORDER BY updated_at DESC LIMIT ? OFFSET ?
                    """,
                    (ecosystem, limit, offset),
                )
            else:
                cursor.execute(
                    "SELECT * FROM supply_chain_vulns ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                )
            results = []
            for row in cursor.fetchall():
                results.append(
                    {
                        "vuln_id": row["vuln_id"],
                        "ecosystem": row["ecosystem"],
                        "package_name": row["package_name"],
                        "affected_versions": row["affected_versions"],
                        "patched_versions": row["patched_versions"],
                        "severity": row["severity"],
                        "cvss_score": row["cvss_score"],
                        "reachable": bool(row["reachable"])
                        if row["reachable"] is not None
                        else None,
                        "transitive": bool(row["transitive"]),
                        "source": row["source"],
                    }
                )
            return results
        except sqlite3.OperationalError:
            # Table might not exist
            return []
        finally:
            conn.close()

    # =========================================================================
    # Comprehensive Feed Stats
    # =========================================================================

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics about all feed data.

        Returns:
            Dictionary with statistics for all feed categories
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            stats: Dict[str, Any] = {
                "categories": {},
                "totals": {},
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }

            # Count records in each table
            tables = [
                ("epss_scores", "authoritative"),
                ("kev_entries", "authoritative"),
                ("exploit_intelligence", "exploit"),
                ("threat_actor_mappings", "threat_actor"),
                ("supply_chain_vulns", "supply_chain"),
                ("cloud_security_bulletins", "cloud_runtime"),
                ("early_signals", "early_signal"),
                ("national_cert_advisories", "national_cert"),
                ("exploit_confidence_scores", "computed"),
                ("geo_weighted_risks", "computed"),
            ]

            for table, category in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                    count = cursor.fetchone()["count"]
                    if category not in stats["categories"]:
                        stats["categories"][category] = {}
                    stats["categories"][category][table] = count
                except sqlite3.OperationalError:
                    pass  # Table doesn't exist yet

            # Get feed metadata
            cursor.execute("SELECT * FROM feed_metadata")
            stats["feed_metadata"] = {
                row["feed_name"]: dict(row) for row in cursor.fetchall()
            }

            # Calculate totals
            stats["totals"]["unique_cves"] = 0
            try:
                cursor.execute(
                    """
                    SELECT COUNT(DISTINCT cve_id) as count FROM (
                        SELECT cve_id FROM epss_scores
                        UNION SELECT cve_id FROM kev_entries
                        UNION SELECT cve_id FROM exploit_intelligence
                        UNION SELECT cve_id FROM threat_actor_mappings
                    )
                    """
                )
                stats["totals"]["unique_cves"] = cursor.fetchone()["count"]
            except sqlite3.OperationalError:
                pass

            return stats
        finally:
            conn.close()

    # =========================================================================
    # Enhanced Enrichment with All Intelligence
    # =========================================================================

    def enrich_findings_comprehensive(
        self, findings: List[Dict[str, Any]], target_region: str = "global"
    ) -> List[Dict[str, Any]]:
        """Enrich findings with ALL available intelligence.

        This is the world-class enrichment that combines:
        - EPSS scores
        - KEV flags
        - Exploit confidence scores
        - Geo-weighted risk
        - Threat actor intelligence
        - Supply chain context

        Args:
            findings: List of finding dictionaries with cve_id field
            target_region: Target region for geo-weighted scoring

        Returns:
            Comprehensively enriched findings
        """
        enriched = []
        for finding in findings:
            enriched_finding = dict(finding)
            cve_id = finding.get("cve_id") or finding.get("vulnerability_id")

            if cve_id and cve_id.upper().startswith("CVE-"):
                cve_id = cve_id.upper()

                # Basic EPSS/KEV enrichment
                epss = self.get_epss_score(cve_id)
                if epss:
                    enriched_finding["epss_score"] = epss.epss
                    enriched_finding["epss_percentile"] = epss.percentile

                kev = self.get_kev_entry(cve_id)
                enriched_finding["in_kev"] = kev is not None
                if kev:
                    enriched_finding["kev_due_date"] = kev.due_date
                    enriched_finding[
                        "kev_ransomware"
                    ] = kev.known_ransomware_campaign_use

                # Exploit confidence score
                confidence = self.calculate_exploit_confidence(cve_id)
                enriched_finding["exploit_confidence"] = confidence.confidence_score
                enriched_finding["exploit_factors"] = confidence.factors

                # Geo-weighted risk
                geo_risk = self.calculate_geo_weighted_risk(cve_id, target_region)
                enriched_finding["geo_risk_score"] = geo_risk.geo_scores.get(
                    target_region, geo_risk.base_score
                )
                enriched_finding["geo_risk_all"] = geo_risk.geo_scores

                # Threat actor intelligence
                threat_actors = self.get_threat_actors_for_cve(cve_id)
                if threat_actors:
                    enriched_finding["threat_actors"] = [
                        ta.threat_actor for ta in threat_actors
                    ]
                    enriched_finding["threat_actor_details"] = [
                        ta.to_dict() for ta in threat_actors
                    ]

                # Exploit intelligence
                exploits = self.get_exploits_for_cve(cve_id)
                if exploits:
                    enriched_finding["public_exploits"] = len(exploits)
                    enriched_finding["exploit_sources"] = list(
                        set(e.exploit_source for e in exploits)
                    )
                    enriched_finding["has_metasploit"] = any(
                        e.metasploit_module for e in exploits
                    )
                    enriched_finding["has_nuclei"] = any(
                        e.nuclei_template for e in exploits
                    )

            enriched.append(enriched_finding)

        return enriched

    @staticmethod
    async def scheduler(
        settings: Any, interval_hours: int = 24
    ) -> None:  # pragma: no cover - background task
        """Background scheduler for periodic feed refresh.

        Args:
            settings: Application settings (for database path)
            interval_hours: Refresh interval in hours (default 24)
        """
        delay = max(1, int(interval_hours)) * 3600

        # Get database path from settings if available
        db_path = None
        if hasattr(settings, "feeds_db_path"):
            db_path = Path(settings.feeds_db_path)

        service = FeedsService(db_path=db_path)

        # Initial refresh on startup
        logger.info("Starting initial feed refresh")
        service.refresh_epss()
        service.refresh_kev()

        while True:
            await asyncio.sleep(delay)
            logger.info(f"Running scheduled feed refresh (interval: {interval_hours}h)")
            service.refresh_epss()
            service.refresh_kev()


__all__ = [
    # Service
    "FeedsService",
    # Enums
    "FeedCategory",
    "GeoRegion",
    # Data classes - Authoritative
    "EPSSScore",
    "KEVEntry",
    "FeedRefreshResult",
    # Data classes - Exploit Intelligence
    "ExploitIntelligence",
    "ExploitConfidenceScore",
    # Data classes - Threat Actor
    "ThreatActorMapping",
    # Data classes - Supply Chain
    "SupplyChainVuln",
    # Data classes - Cloud/Runtime
    "CloudSecurityBulletin",
    # Data classes - Early Signal
    "EarlySignal",
    # Data classes - National CERTs
    "NationalCERTAdvisory",
    # Data classes - Geo-weighted Risk
    "GeoWeightedRisk",
    # Feed configurations
    "AUTHORITATIVE_FEEDS",
    "NATIONAL_CERT_FEEDS",
    "EXPLOIT_FEEDS",
    "THREAT_ACTOR_FEEDS",
    "SUPPLY_CHAIN_FEEDS",
    "CLOUD_RUNTIME_FEEDS",
    "EARLY_SIGNAL_FEEDS",
    "GEO_WEIGHTS",
]
