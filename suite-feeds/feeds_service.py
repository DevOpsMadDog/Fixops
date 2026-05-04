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
import os
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
    "cisa_vulnrichment": {
        "name": "CISA Vulnrichment (SSVC Decision Points + ADP)",
        "url": "https://api.github.com/repos/cisagov/vulnrichment/git/trees/develop?recursive=1",
        "format": "json",
        "api_key_required": False,
        "refresh_hours": 12,
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
        "name": "Nuclei Templates (CVE → Template Mapping)",
        "url": "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json",
        "git_repo": "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1",
        "format": "json",
        "refresh_hours": 24,
    },
    "poc_in_github": {
        "name": "PoC-in-GitHub (Public Exploit PoCs)",
        "url": "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/master?recursive=1",
        "format": "json",
        "api_key_required": False,
        "refresh_hours": 12,
    },
    "inthewild": {
        "name": "InTheWild.io (Exploitation-in-the-Wild)",
        "url": "https://inthewild.io/api/exploited",
        "format": "json",
        "api_key_required": False,
        "refresh_hours": 6,
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
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_entries(date_added)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_kev_ransomware ON kev_entries(known_ransomware_campaign_use)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_kev_vendor ON kev_entries(vendor_project)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_kev_due_date ON kev_entries(due_date)"
        )

        # NVD CVEs table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS nvd_cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                cwe_ids TEXT,
                affected_packages TEXT,
                references_json TEXT,
                published TEXT,
                modified TEXT,
                source_identifier TEXT,
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
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_nvd_severity ON nvd_cves(severity)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_nvd_published ON nvd_cves(published)"
        )

        # VEDAS (Vulnerability & Exploit Data Aggregation System) scores table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vedas_scores (
                cve_id TEXT PRIMARY KEY,
                epss REAL NOT NULL,
                vedas REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
        """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vedas_score ON vedas_scores(vedas)"
        )

        # CISA Vulnrichment — SSVC decision points + ADP enrichments
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnrichment (
                cve_id TEXT PRIMARY KEY,
                ssvc_exploitation TEXT,
                ssvc_automatable TEXT,
                ssvc_technical_impact TEXT,
                ssvc_action TEXT,
                adp_provider TEXT,
                affected_products TEXT,
                reference_urls TEXT,
                date_added TEXT,
                updated_at TEXT NOT NULL
            )
        """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnrichment_action ON vulnrichment(ssvc_action)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnrichment_exploitation ON vulnrichment(ssvc_exploitation)"
        )

        # PoC-in-GitHub — public exploit proof-of-concepts
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS poc_in_github (
                cve_id TEXT NOT NULL,
                repo_url TEXT NOT NULL,
                description TEXT,
                stargazers_count INTEGER DEFAULT 0,
                forks_count INTEGER DEFAULT 0,
                created_at TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE(cve_id, repo_url)
            )
        """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_poc_cve ON poc_in_github(cve_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_poc_stars ON poc_in_github(stargazers_count)"
        )

        # InTheWild — exploitation-in-the-wild signals
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS inthewild_exploited (
                cve_id TEXT PRIMARY KEY,
                first_seen TEXT,
                source TEXT,
                source_url TEXT,
                updated_at TEXT NOT NULL
            )
        """
        )

        # Nuclei Templates — CVE to nuclei template mapping
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS nuclei_templates (
                cve_id TEXT NOT NULL,
                template_path TEXT NOT NULL,
                template_url TEXT,
                severity TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE(cve_id, template_path)
            )
        """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_nuclei_cve ON nuclei_templates(cve_id)"
        )

        conn.commit()
        conn.close()


    @staticmethod
    def _get_github_token() -> Optional[str]:
        """Get GitHub API token from environment for higher rate limits."""
        import os
        return os.getenv("GITHUB_TOKEN") or os.getenv("FIXOPS_GITHUB_TOKEN") or None

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
                        "model_version", datetime.now(timezone.utc).strftime("%Y-%m-%d")
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

            logger.info("EPSS refresh complete: %d records updated", len(records))

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
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

            logger.info("KEV refresh complete: %d records updated", len(records))

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
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            error_msg = f"Error processing KEV feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="kev",
                success=False,
                records_updated=0,
                error=error_msg,
            )

    def refresh_nvd(self, days: int = 7) -> FeedRefreshResult:
        """Refresh NVD CVE data from NIST NVD 2.0 API.

        Downloads recent CVEs published/modified in the last N days.

        Args:
            days: Number of days to look back (default 7)

        Returns:
            FeedRefreshResult with refresh status
        """
        try:
            from datetime import timedelta

            logger.info("Refreshing NVD CVEs from NIST (last %d days)", days)

            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=days)

            url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
                f"pubStartDate={start_date.strftime('%Y-%m-%dT%H:%M:%S.000')}&"
                f"pubEndDate={end_date.strftime('%Y-%m-%dT%H:%M:%S.000')}"
            )

            # NVD API key gives 50 req/30s vs 5 req/30s unauthenticated
            nvd_headers: dict = {}
            nvd_api_key = os.environ.get("NVD_API_KEY", "")
            if nvd_api_key:
                nvd_headers["apiKey"] = nvd_api_key
                logger.info("NVD: using authenticated request (higher rate limit)")

            response = requests.get(url, headers=nvd_headers, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            records = []
            for vuln_item in vulnerabilities:
                cve = vuln_item.get("cve", {})
                cve_id = cve.get("id", "").strip()
                if not cve_id:
                    continue

                # Extract description (English)
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                # Extract CVSS metrics
                metrics = cve.get("metrics", {})
                cvss_score = None
                cvss_vector = None
                severity = None

                cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get(
                    "cvssMetricV30", []
                )
                if cvss_v3:
                    cvss_data = cvss_v3[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    severity = cvss_data.get("baseSeverity", "").upper() or None

                if not cvss_score:
                    cvss_v2 = metrics.get("cvssMetricV2", [])
                    if cvss_v2:
                        cvss_data = cvss_v2[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString")
                        if cvss_score:
                            severity = (
                                "HIGH"
                                if cvss_score >= 7.0
                                else "MEDIUM"
                                if cvss_score >= 4.0
                                else "LOW"
                            )

                # Extract CWE IDs
                cwe_ids = []
                for weakness in cve.get("weaknesses", []):
                    for wd in weakness.get("description", []):
                        val = wd.get("value", "")
                        if val.startswith("CWE-"):
                            cwe_ids.append(val)

                # Extract affected packages from CPE
                affected = []
                for config in cve.get("configurations", []):
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            cpe = match.get("criteria", "")
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                affected.append(f"{parts[3]}/{parts[4]}")

                # Extract references
                refs = [
                    r.get("url", "") for r in cve.get("references", []) if r.get("url")
                ]

                records.append(
                    {
                        "cve_id": cve_id,
                        "description": desc,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "cwe_ids": json.dumps(cwe_ids),
                        "affected_packages": json.dumps(list(set(affected))),
                        "references_json": json.dumps(refs[:20]),
                        "published": cve.get("published"),
                        "modified": cve.get("lastModified"),
                        "source_identifier": cve.get("sourceIdentifier"),
                    }
                )

            # Batch insert into database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()

            cursor.executemany(
                """
                INSERT OR REPLACE INTO nvd_cves
                (cve_id, description, severity, cvss_score, cvss_vector,
                 cwe_ids, affected_packages, references_json, published,
                 modified, source_identifier, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                [
                    (
                        r["cve_id"],
                        r["description"],
                        r["severity"],
                        r["cvss_score"],
                        r["cvss_vector"],
                        r["cwe_ids"],
                        r["affected_packages"],
                        r["references_json"],
                        r["published"],
                        r["modified"],
                        r["source_identifier"],
                        now,
                    )
                    for r in records
                ],
            )

            cursor.execute(
                """INSERT OR REPLACE INTO feed_metadata
                   (feed_name, last_refresh, records_count, status)
                   VALUES (?, ?, ?, ?)""",
                ("nvd", now, len(records), "success"),
            )

            conn.commit()
            conn.close()

            logger.info("NVD refresh complete: %d CVEs updated", len(records))

            return FeedRefreshResult(
                feed_name="nvd",
                success=True,
                records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch NVD feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="nvd", success=False, records_updated=0, error=error_msg
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            error_msg = f"Error processing NVD feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="nvd", success=False, records_updated=0, error=error_msg
            )

    def refresh_exploitdb(self) -> FeedRefreshResult:
        """Refresh exploit intelligence from Exploit-DB CSV on GitLab.

        Downloads the public Exploit-DB CSV and stores exploit data.

        Returns:
            FeedRefreshResult with refresh status
        """
        try:
            logger.info("Refreshing ExploitDB from GitLab mirror")

            url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()

            lines = response.text.splitlines()
            reader = csv.DictReader(lines)
            records = []

            for row in reader:
                exploit_id = row.get("id", "").strip()
                if not exploit_id:
                    continue

                description = row.get("description", "")
                platform = row.get("platform", "")
                exploit_type = row.get("type", "")
                date_published = row.get("date_published", "")

                # Try to extract CVE from description
                import re

                cve_match = re.search(r"CVE-\d{4}-\d{4,}", description)
                cve_id = cve_match.group(0) if cve_match else ""

                records.append(
                    {
                        "cve_id": cve_id or f"EDB-{exploit_id}",
                        "exploit_source": "exploit-db",
                        "exploit_type": exploit_type,
                        "exploit_url": f"https://www.exploit-db.com/exploits/{exploit_id}",
                        "exploit_date": date_published,
                        "verified": row.get("verified", "0") == "1",
                        "reliability": "good"
                        if row.get("verified", "0") == "1"
                        else "normal",
                        "platform": platform,
                        "description": description,
                    }
                )

            # Batch insert into database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()

            cursor.executemany(
                """
                INSERT OR REPLACE INTO exploit_intelligence
                (cve_id, exploit_source, exploit_type, exploit_url,
                 exploit_date, verified, reliability, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                [
                    (
                        r["cve_id"],
                        r["exploit_source"],
                        r["exploit_type"],
                        r["exploit_url"],
                        r["exploit_date"],
                        1 if r["verified"] else 0,
                        r["reliability"],
                        now,
                    )
                    for r in records
                ],
            )

            cursor.execute(
                """INSERT OR REPLACE INTO feed_metadata
                   (feed_name, last_refresh, records_count, status)
                   VALUES (?, ?, ?, ?)""",
                ("exploitdb", now, len(records), "success"),
            )

            conn.commit()
            conn.close()

            logger.info("ExploitDB refresh complete: %d exploits updated", len(records))

            return FeedRefreshResult(
                feed_name="exploitdb",
                success=True,
                records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch ExploitDB feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="exploitdb", success=False, records_updated=0, error=error_msg
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            error_msg = f"Error processing ExploitDB feed: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="exploitdb", success=False, records_updated=0, error=error_msg
            )

    def refresh_osv(self, ecosystems: Optional[List[str]] = None) -> FeedRefreshResult:
        """Refresh OSV (Open Source Vulnerabilities) data.

        Downloads vulnerability data from Google's OSV database for specified ecosystems.

        Args:
            ecosystems: List of ecosystems to refresh (default: PyPI, npm, Go, Maven, crates.io)

        Returns:
            FeedRefreshResult with refresh status
        """
        try:
            if ecosystems is None:
                ecosystems = ["PyPI", "npm", "Go", "Maven", "crates.io"]

            logger.info("Refreshing OSV for ecosystems: %s", ecosystems)

            total_records = 0
            for ecosystem in ecosystems:
                try:
                    # Use OSV.dev API for batch queries
                    api_url = "https://api.osv.dev/v1/query"
                    # Query for recent vulns in this ecosystem
                    payload = {
                        "package": {"ecosystem": ecosystem},
                    }
                    response = requests.post(
                        api_url, json=payload, timeout=self.timeout
                    )
                    response.raise_for_status()

                    data = response.json()
                    vulns = data.get("vulns", [])

                    records = []
                    for vuln in vulns[:500]:  # Limit per ecosystem
                        vuln_id = vuln.get("id", "")
                        if not vuln_id:
                            continue

                        vuln.get("summary", "")
                        severity = None
                        cvss_score = None
                        for sev in vuln.get("severity", []):
                            if sev.get("type") == "CVSS_V3":
                                vec = sev.get("score", "")
                                if "/" in vec:
                                    try:
                                        cvss_score = float(
                                            vec.split("/")[0].split(":")[-1]
                                        )
                                    except (ValueError, IndexError):
                                        pass

                        if cvss_score:
                            severity = (
                                "CRITICAL"
                                if cvss_score >= 9.0
                                else "HIGH"
                                if cvss_score >= 7.0
                                else "MEDIUM"
                                if cvss_score >= 4.0
                                else "LOW"
                            )

                        # Extract affected packages
                        pkg_names = []
                        affected_vers = []
                        patched_vers = []
                        for aff in vuln.get("affected", []):
                            pkg = aff.get("package", {})
                            name = pkg.get("name", "")
                            if name:
                                pkg_names.append(name)
                            for rng in aff.get("ranges", []):
                                for evt in rng.get("events", []):
                                    if "introduced" in evt:
                                        affected_vers.append(evt["introduced"])
                                    if "fixed" in evt:
                                        patched_vers.append(evt["fixed"])

                        records.append(
                            {
                                "vuln_id": vuln_id,
                                "ecosystem": ecosystem,
                                "package_name": ", ".join(pkg_names[:5]),
                                "affected_versions": ", ".join(affected_vers[:10]),
                                "patched_versions": ", ".join(patched_vers[:10])
                                or None,
                                "severity": severity or "unknown",
                                "cvss_score": cvss_score,
                                "source": "osv",
                            }
                        )

                    # Store in supply_chain_vulns
                    if records:
                        conn = sqlite3.connect(self.db_path)
                        cursor = conn.cursor()
                        now = datetime.now(timezone.utc).isoformat()

                        cursor.executemany(
                            """
                            INSERT OR REPLACE INTO supply_chain_vulns
                            (vuln_id, ecosystem, package_name, affected_versions,
                             patched_versions, severity, cvss_score, source, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                            [
                                (
                                    r["vuln_id"],
                                    r["ecosystem"],
                                    r["package_name"],
                                    r["affected_versions"],
                                    r["patched_versions"],
                                    r["severity"],
                                    r["cvss_score"],
                                    r["source"],
                                    now,
                                )
                                for r in records
                            ],
                        )
                        conn.commit()
                        conn.close()

                    total_records += len(records)
                    logger.info(
                        "OSV %s: %d vulnerabilities fetched", ecosystem, len(records)
                    )

                except (OSError, ValueError, KeyError, RuntimeError) as eco_exc:  # narrowed from bare Exception
                    logger.warning("OSV %s failed: %s", ecosystem, eco_exc)
                    continue

            # Update metadata
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                """INSERT OR REPLACE INTO feed_metadata
                   (feed_name, last_refresh, records_count, status)
                   VALUES (?, ?, ?, ?)""",
                ("osv", now, total_records, "success"),
            )
            conn.commit()
            conn.close()

            logger.info("OSV refresh complete: %d total records", total_records)

            return FeedRefreshResult(
                feed_name="osv",
                success=True,
                records_updated=total_records,
            )

        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            error_msg = f"Error processing OSV feeds: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="osv", success=False, records_updated=0, error=error_msg
            )

    def refresh_github_advisories(self) -> FeedRefreshResult:
        """Refresh GitHub Security Advisories via REST API.

        Uses the public GitHub Advisory Database REST API (no auth required).

        Returns:
            FeedRefreshResult with refresh status
        """
        try:
            logger.info("Refreshing GitHub Security Advisories")

            url = "https://api.github.com/advisories"
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            params = {
                "per_page": 100,
                "sort": "published",
                "direction": "desc",
                "type": "reviewed",
            }

            response = requests.get(
                url, headers=headers, params=params, timeout=self.timeout
            )
            response.raise_for_status()

            advisories = response.json()
            records = []

            for adv in advisories:
                ghsa_id = adv.get("ghsa_id", "")
                if not ghsa_id:
                    continue

                adv.get("summary", "")
                severity = (adv.get("severity") or "unknown").upper()
                cvss_score = None
                cvss = adv.get("cvss")
                if cvss and isinstance(cvss, dict):
                    cvss_score = cvss.get("score")
                elif cvss and isinstance(cvss, (int, float)):
                    cvss_score = float(cvss)
                elif cvss and isinstance(cvss, str):
                    try:
                        cvss_score = float(cvss)
                    except (ValueError, TypeError):
                        cvss_score = None

                # Extract CVE aliases
                cve_id = adv.get("cve_id", "") or ""

                # Extract affected packages
                for vuln in adv.get("vulnerabilities", []):
                    if not isinstance(vuln, dict):
                        continue
                    pkg = vuln.get("package", {})
                    if isinstance(pkg, str):
                        pkg_name = pkg
                        ecosystem = ""
                    elif isinstance(pkg, dict):
                        pkg_name = pkg.get("name", "")
                        ecosystem = pkg.get("ecosystem", "")
                    else:
                        pkg_name = ""
                        ecosystem = ""
                    vuln_range = vuln.get("vulnerable_version_range", "")
                    fpv = vuln.get("first_patched_version")
                    if isinstance(fpv, dict):
                        patched = fpv.get("identifier", "")
                    elif isinstance(fpv, str):
                        patched = fpv
                    else:
                        patched = ""

                    vid = cve_id if cve_id else ghsa_id
                    records.append(
                        {
                            "vuln_id": vid,
                            "ecosystem": ecosystem,
                            "package_name": pkg_name,
                            "affected_versions": vuln_range,
                            "patched_versions": patched,
                            "severity": severity,
                            "cvss_score": cvss_score,
                            "source": "github",
                        }
                    )

            # Store in supply_chain_vulns
            if records:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                now = datetime.now(timezone.utc).isoformat()

                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO supply_chain_vulns
                    (vuln_id, ecosystem, package_name, affected_versions,
                     patched_versions, severity, cvss_score, source, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    [
                        (
                            r["vuln_id"],
                            r["ecosystem"],
                            r["package_name"],
                            r["affected_versions"],
                            r["patched_versions"],
                            r["severity"],
                            r["cvss_score"],
                            r["source"],
                            now,
                        )
                        for r in records
                    ],
                )

                cursor.execute(
                    """INSERT OR REPLACE INTO feed_metadata
                       (feed_name, last_refresh, records_count, status)
                       VALUES (?, ?, ?, ?)""",
                    ("github_advisories", now, len(records), "success"),
                )

                conn.commit()
                conn.close()

            logger.info("GitHub Advisory refresh complete: %d records", len(records))

            return FeedRefreshResult(
                feed_name="github_advisories",
                success=True,
                records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch GitHub advisories: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="github_advisories",
                success=False,
                records_updated=0,
                error=error_msg,
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            error_msg = f"Error processing GitHub advisories: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="github_advisories",
                success=False,
                records_updated=0,
                error=error_msg,
            )

    # =========================================================================
    # VEDAS (ARPSyndicate) Feed Methods
    # =========================================================================

    def refresh_vedas(self) -> FeedRefreshResult:
        """Refresh VEDAS scores from ARPSyndicate CVE-Scores dataset.

        Downloads the VEDAS (Vulnerability & Exploit Data Aggregation System)
        scores CSV which provides an alternative vulnerability scoring to EPSS.
        Source: https://github.com/ARPSyndicate/cve-scores

        Returns:
            FeedRefreshResult with success status and record count
        """
        url = "https://raw.githubusercontent.com/ARPSyndicate/cve-scores/master/cve-scores.csv"
        logger.info("Refreshing VEDAS scores from %s", url)

        try:
            resp = requests.get(url, timeout=self.timeout, stream=True)
            resp.raise_for_status()

            now = datetime.now(timezone.utc).isoformat()
            records: list[tuple] = []

            # Parse CSV — format: CVE,EPSS,VEDAS (with header)
            lines = resp.iter_lines(decode_unicode=True)
            header = next(lines, None)  # skip header
            if header is None:
                return FeedRefreshResult(
                    feed_name="vedas",
                    success=False,
                    records_updated=0,
                    error="Empty CSV response from VEDAS feed",
                )

            for line in lines:
                if not line or not line.startswith("CVE-"):
                    continue
                parts = line.split(",")
                if len(parts) != 3:
                    continue
                try:
                    cve_id = parts[0].strip()
                    epss_val = float(parts[1].strip())
                    vedas_val = float(parts[2].strip())
                    records.append((cve_id, epss_val, vedas_val, now))
                except (ValueError, IndexError):
                    continue

            if records:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                # Batch insert with chunking for large datasets
                chunk_size = 5000
                for i in range(0, len(records), chunk_size):
                    chunk = records[i : i + chunk_size]
                    cursor.executemany(
                        """INSERT OR REPLACE INTO vedas_scores
                           (cve_id, epss, vedas, updated_at)
                           VALUES (?, ?, ?, ?)""",
                        chunk,
                    )

                cursor.execute(
                    """INSERT OR REPLACE INTO feed_metadata
                       (feed_name, last_refresh, records_count, status)
                       VALUES (?, ?, ?, ?)""",
                    ("vedas", now, len(records), "success"),
                )

                conn.commit()
                conn.close()

            logger.info("VEDAS refresh complete: %d records", len(records))

            return FeedRefreshResult(
                feed_name="vedas",
                success=True,
                records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch VEDAS scores: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="vedas",
                success=False,
                records_updated=0,
                error=error_msg,
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            error_msg = f"Error processing VEDAS scores: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(
                feed_name="vedas",
                success=False,
                records_updated=0,
                error=error_msg,
            )

    def get_vedas_score(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get VEDAS score for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            Dict with VEDAS data if found, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vedas_scores WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_vedas_high_risk(
        self, threshold: float = 0.7, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get CVEs with high VEDAS scores.

        Args:
            threshold: Minimum VEDAS score (default: 0.7)
            limit: Maximum results to return

        Returns:
            List of CVE dicts with high VEDAS scores
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM vedas_scores WHERE vedas >= ? ORDER BY vedas DESC LIMIT ?",
            (threshold, limit),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # =========================================================================
    # CISA Vulnrichment (SSVC Decision Intelligence)
    # =========================================================================

    def refresh_vulnrichment(self) -> FeedRefreshResult:
        """Refresh SSVC decision points from CISA Vulnrichment (cisagov/vulnrichment).

        Downloads CVE enrichment files from the CISA Vulnrichment GitHub repo.
        Each file contains SSVC decision points (Exploitation, Automatable,
        Technical Impact) and ADP (Authorized Data Publisher) enrichments.

        The SSVC framework answers "should you act?" — not "how bad is it?"
        This is the single most important enrichment for actionable triage.

        Returns:
            FeedRefreshResult with success status and record count
        """
        # We use the GitHub API to list CVE files, then fetch a batch of recent ones.
        # Full repo has 40k+ files — we fetch the tree and parse CVE IDs from paths.
        tree_url = "https://api.github.com/repos/cisagov/vulnrichment/git/trees/develop?recursive=1"
        logger.info("Refreshing CISA Vulnrichment from %s", tree_url)

        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            gh_token = self._get_github_token()
            if gh_token:
                headers["Authorization"] = f"token {gh_token}"

            resp = requests.get(tree_url, timeout=self.timeout, headers=headers)
            resp.raise_for_status()
            tree_data = resp.json()

            # Filter for CVE JSON files: paths like "2024/CVE-2024-1234.json"
            import re as _re
            cve_files = []
            for item in tree_data.get("tree", []):
                path = item.get("path", "")
                if path.endswith(".json") and "/CVE-" in path:
                    # Extract CVE ID from filename
                    match = _re.search(r"(CVE-\d{4}-\d{4,})", path)
                    if match:
                        cve_files.append((match.group(1), path))

            if not cve_files:
                return FeedRefreshResult(
                    feed_name="vulnrichment",
                    success=True,
                    records_updated=0,
                    error="No CVE files found in repo tree",
                )

            # Fetch the most recent CVE files (sort by year desc, limit batch)
            cve_files.sort(key=lambda x: x[0], reverse=True)
            batch = cve_files[:500]  # Latest 500 CVEs

            now = datetime.now(timezone.utc).isoformat()
            records: list[tuple] = []

            for cve_id, path in batch:
                raw_url = f"https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{path}"
                try:
                    file_resp = requests.get(raw_url, timeout=15, headers=headers)
                    if file_resp.status_code != 200:
                        continue
                    cve_data = file_resp.json()

                    # Extract SSVC decision points from ADP containers
                    ssvc = self._extract_ssvc(cve_data)
                    adp_provider = ""
                    affected = ""
                    refs = ""

                    # Parse ADP containers
                    containers = cve_data.get("containers", {})
                    adp_list = containers.get("adp", [])
                    if isinstance(adp_list, list):
                        for adp in adp_list:
                            adp_provider = adp.get("providerOrgId", adp_provider)
                            affected_list = adp.get("affected", [])
                            if affected_list:
                                affected = json.dumps(affected_list[:20])
                            ref_list = adp.get("references", [])
                            if ref_list:
                                refs = json.dumps([r.get("url", "") for r in ref_list[:10]])

                    records.append((
                        cve_id,
                        ssvc.get("exploitation", ""),
                        ssvc.get("automatable", ""),
                        ssvc.get("technical_impact", ""),
                        ssvc.get("action", ""),
                        adp_provider,
                        affected,
                        refs,
                        ssvc.get("date_added", ""),
                        now,
                    ))

                except (RequestException, json.JSONDecodeError, KeyError):
                    continue

            if records:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.executemany(
                    """INSERT OR REPLACE INTO vulnrichment
                       (cve_id, ssvc_exploitation, ssvc_automatable, ssvc_technical_impact,
                        ssvc_action, adp_provider, affected_products, reference_urls,
                        date_added, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    records,
                )
                cursor.execute(
                    """INSERT OR REPLACE INTO feed_metadata
                       (feed_name, last_refresh, records_count, status)
                       VALUES (?, ?, ?, ?)""",
                    ("vulnrichment", now, len(records), "success"),
                )
                conn.commit()
                conn.close()

            logger.info("Vulnrichment refresh complete: %d SSVC records", len(records))
            return FeedRefreshResult(
                feed_name="vulnrichment",
                success=True,
                records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch Vulnrichment: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(feed_name="vulnrichment", success=False, records_updated=0, error=error_msg)
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            error_msg = f"Error processing Vulnrichment: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(feed_name="vulnrichment", success=False, records_updated=0, error=error_msg)

    @staticmethod
    def _extract_ssvc(cve_data: Dict[str, Any]) -> Dict[str, str]:
        """Extract SSVC decision points from a Vulnrichment CVE record."""
        ssvc: Dict[str, str] = {}
        containers = cve_data.get("containers", {})
        adp_list = containers.get("adp", [])
        if not isinstance(adp_list, list):
            return ssvc
        for adp in adp_list:
            metrics = adp.get("metrics", [])
            for metric_block in metrics:
                other = metric_block.get("other", {})
                content = other.get("content", {})
                if not content:
                    continue
                # SSVC fields
                for key in ("exploitation", "automatable", "technical_impact"):
                    val = content.get(key) or content.get(key.replace("_", " ").title())
                    if val:
                        ssvc[key] = str(val).lower()
                # SSVC recommended action
                options = content.get("options", [])
                if isinstance(options, list):
                    for opt in options:
                        if isinstance(opt, dict) and opt.get("Exploitation"):
                            ssvc["exploitation"] = str(opt["Exploitation"]).lower()
                        if isinstance(opt, dict) and opt.get("Automatable"):
                            ssvc["automatable"] = str(opt["Automatable"]).lower()
                        if isinstance(opt, dict) and opt.get("Technical Impact"):
                            ssvc["technical_impact"] = str(opt["Technical Impact"]).lower()
                # Decision / action
                action = content.get("action") or content.get("Action")
                if action:
                    ssvc["action"] = str(action).lower()
            # Also check providerMetadata for date
            prov = adp.get("providerMetadata", {})
            ssvc["date_added"] = prov.get("dateUpdated", "")
        return ssvc

    def get_vulnrichment(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get SSVC decision points for a CVE from local Vulnrichment data."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vulnrichment WHERE cve_id = ?", (cve_id.upper(),))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        result = dict(row)
        # Parse JSON fields
        for field_name in ("affected_products", "reference_urls"):
            raw = result.get(field_name)
            if raw:
                try:
                    result[field_name] = json.loads(raw)
                except json.JSONDecodeError:
                    pass
        return result

    def get_ssvc_actionable(self, action: str = "act", limit: int = 100) -> List[Dict[str, Any]]:
        """Get CVEs where SSVC recommends a specific action (act, attend, track, track*)."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM vulnrichment WHERE ssvc_action = ? ORDER BY updated_at DESC LIMIT ?",
            (action.lower(), limit),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # =========================================================================
    # PoC-in-GitHub (Public Exploit PoC Tracking)
    # =========================================================================

    def refresh_poc_in_github(self) -> FeedRefreshResult:
        """Refresh public exploit PoC data from nomi-sec/PoC-in-GitHub.

        This repo auto-collects GitHub repositories that contain proof-of-concept
        exploits mapped to CVE IDs. Answers: "Does a weaponized exploit exist?"

        The repo structure is: {year}/{CVE-ID}.json — each JSON file contains
        a list of GitHub repos with PoC code for that CVE.

        Returns:
            FeedRefreshResult with success status and record count
        """
        tree_url = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/master?recursive=1"
        logger.info("Refreshing PoC-in-GitHub from %s", tree_url)

        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            gh_token = self._get_github_token()
            if gh_token:
                headers["Authorization"] = f"token {gh_token}"

            resp = requests.get(tree_url, timeout=self.timeout, headers=headers)
            resp.raise_for_status()
            tree_data = resp.json()

            import re as _re
            cve_files = []
            for item in tree_data.get("tree", []):
                path = item.get("path", "")
                if path.endswith(".json") and "CVE-" in path:
                    match = _re.search(r"(CVE-\d{4}-\d{4,})", path)
                    if match:
                        cve_files.append((match.group(1), path))

            if not cve_files:
                return FeedRefreshResult(
                    feed_name="poc_in_github", success=True, records_updated=0,
                    error="No CVE files found in PoC-in-GitHub tree",
                )

            # Fetch most recent CVE PoC files
            cve_files.sort(key=lambda x: x[0], reverse=True)
            batch = cve_files[:300]

            now = datetime.now(timezone.utc).isoformat()
            records: list[tuple] = []

            for cve_id, path in batch:
                raw_url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{path}"
                try:
                    file_resp = requests.get(raw_url, timeout=15, headers=headers)
                    if file_resp.status_code != 200:
                        continue
                    poc_list = file_resp.json()
                    if not isinstance(poc_list, list):
                        continue

                    for poc in poc_list[:10]:  # Cap at 10 PoCs per CVE
                        repo_url = poc.get("html_url") or poc.get("url", "")
                        if not repo_url:
                            continue
                        records.append((
                            cve_id,
                            repo_url,
                            (poc.get("description") or "")[:500],
                            poc.get("stargazers_count", 0),
                            poc.get("forks_count", 0),
                            poc.get("created_at", ""),
                            now,
                        ))

                except (RequestException, json.JSONDecodeError, KeyError):
                    continue

            if records:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                chunk_size = 2000
                for i in range(0, len(records), chunk_size):
                    chunk = records[i : i + chunk_size]
                    cursor.executemany(
                        """INSERT OR REPLACE INTO poc_in_github
                           (cve_id, repo_url, description, stargazers_count,
                            forks_count, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        chunk,
                    )
                cursor.execute(
                    """INSERT OR REPLACE INTO feed_metadata
                       (feed_name, last_refresh, records_count, status)
                       VALUES (?, ?, ?, ?)""",
                    ("poc_in_github", now, len(records), "success"),
                )
                conn.commit()
                conn.close()

            logger.info("PoC-in-GitHub refresh complete: %d PoC records", len(records))
            return FeedRefreshResult(
                feed_name="poc_in_github", success=True, records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch PoC-in-GitHub: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(feed_name="poc_in_github", success=False, records_updated=0, error=error_msg)
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            error_msg = f"Error processing PoC-in-GitHub: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(feed_name="poc_in_github", success=False, records_updated=0, error=error_msg)

    def get_poc_for_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get public PoC exploits for a CVE."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM poc_in_github WHERE cve_id = ? ORDER BY stargazers_count DESC",
            (cve_id.upper(),),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def has_public_exploit(self, cve_id: str) -> bool:
        """Check if a CVE has any public exploit PoC on GitHub."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM poc_in_github WHERE cve_id = ? LIMIT 1", (cve_id.upper(),))
        result = cursor.fetchone()
        conn.close()
        return result is not None

    # =========================================================================
    # InTheWild.io (Exploitation-in-the-Wild Signals)
    # =========================================================================

    def refresh_inthewild(self) -> FeedRefreshResult:
        """Refresh exploitation-in-the-wild signals from inthewild.io.

        This feed tracks CVEs that have been observed being actively exploited
        in the wild, with source attribution. Complements CISA KEV with
        broader, faster coverage from the security community.

        Returns:
            FeedRefreshResult with success status and record count
        """
        api_url = "https://inthewild.io/api/exploited"
        logger.info("Refreshing InTheWild.io from %s", api_url)

        try:
            resp = requests.get(api_url, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()

            if not isinstance(data, list):
                return FeedRefreshResult(
                    feed_name="inthewild", success=True, records_updated=0,
                    error="Unexpected response format from InTheWild API",
                )

            now = datetime.now(timezone.utc).isoformat()
            records: list[tuple] = []

            for entry in data:
                cve_id = entry.get("cve") or entry.get("id") or ""
                if not cve_id.upper().startswith("CVE-"):
                    continue
                records.append((
                    cve_id.upper(),
                    entry.get("first_seen") or entry.get("firstSeen", ""),
                    entry.get("source") or entry.get("reporter", ""),
                    entry.get("source_url") or entry.get("sourceUrl", ""),
                    now,
                ))

            if records:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.executemany(
                    """INSERT OR REPLACE INTO inthewild_exploited
                       (cve_id, first_seen, source, source_url, updated_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    records,
                )
                cursor.execute(
                    """INSERT OR REPLACE INTO feed_metadata
                       (feed_name, last_refresh, records_count, status)
                       VALUES (?, ?, ?, ?)""",
                    ("inthewild", now, len(records), "success"),
                )
                conn.commit()
                conn.close()

            logger.info("InTheWild refresh complete: %d exploitation signals", len(records))
            return FeedRefreshResult(
                feed_name="inthewild", success=True, records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch InTheWild: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(feed_name="inthewild", success=False, records_updated=0, error=error_msg)
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            error_msg = f"Error processing InTheWild: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(feed_name="inthewild", success=False, records_updated=0, error=error_msg)

    def is_exploited_in_wild(self, cve_id: str) -> bool:
        """Check if a CVE is being actively exploited in the wild (via InTheWild.io)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM inthewild_exploited WHERE cve_id = ? LIMIT 1", (cve_id.upper(),))
        result = cursor.fetchone()
        conn.close()
        return result is not None

    def get_inthewild_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get exploitation-in-the-wild data for a CVE."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM inthewild_exploited WHERE cve_id = ?", (cve_id.upper(),))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    # =========================================================================
    # Nuclei Templates (CVE → Validation Template Mapping)
    # =========================================================================

    def refresh_nuclei_templates(self) -> FeedRefreshResult:
        """Refresh CVE-to-Nuclei-template mappings from projectdiscovery/nuclei-templates.

        Maps CVE IDs to their corresponding Nuclei scanning templates, enabling
        "One-Click Validation" — verify if a vulnerability is exploitable using
        the exact template from the nuclei-templates repository.

        Returns:
            FeedRefreshResult with success status and record count
        """
        tree_url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
        logger.info("Refreshing Nuclei Templates from %s", tree_url)

        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            gh_token = self._get_github_token()
            if gh_token:
                headers["Authorization"] = f"token {gh_token}"

            resp = requests.get(tree_url, timeout=self.timeout, headers=headers)
            resp.raise_for_status()
            tree_data = resp.json()

            import re as _re
            now = datetime.now(timezone.utc).isoformat()
            records: list[tuple] = []

            for item in tree_data.get("tree", []):
                path = item.get("path", "")
                if not path.endswith(".yaml"):
                    continue
                # Match CVE references in template paths: e.g., "http/cves/2024/CVE-2024-1234.yaml"
                match = _re.search(r"(CVE-\d{4}-\d{4,})", path)
                if not match:
                    continue
                cve_id = match.group(1)
                template_url = f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{path}"

                # Infer severity from path segments
                severity = "unknown"
                path_lower = path.lower()
                for sev in ("critical", "high", "medium", "low", "info"):
                    if sev in path_lower:
                        severity = sev
                        break

                records.append((cve_id, path, template_url, severity, now))

            if records:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                chunk_size = 2000
                for i in range(0, len(records), chunk_size):
                    chunk = records[i : i + chunk_size]
                    cursor.executemany(
                        """INSERT OR REPLACE INTO nuclei_templates
                           (cve_id, template_path, template_url, severity, updated_at)
                           VALUES (?, ?, ?, ?, ?)""",
                        chunk,
                    )
                cursor.execute(
                    """INSERT OR REPLACE INTO feed_metadata
                       (feed_name, last_refresh, records_count, status)
                       VALUES (?, ?, ?, ?)""",
                    ("nuclei_templates", now, len(records), "success"),
                )
                conn.commit()
                conn.close()

            logger.info("Nuclei Templates refresh complete: %d template mappings", len(records))
            return FeedRefreshResult(
                feed_name="nuclei_templates", success=True, records_updated=len(records),
            )

        except RequestException as exc:
            error_msg = f"Failed to fetch Nuclei Templates: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(feed_name="nuclei_templates", success=False, records_updated=0, error=error_msg)
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            error_msg = f"Error processing Nuclei Templates: {exc}"
            logger.error(error_msg)
            return FeedRefreshResult(feed_name="nuclei_templates", success=False, records_updated=0, error=error_msg)

    def get_nuclei_templates(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get Nuclei validation templates for a CVE."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM nuclei_templates WHERE cve_id = ? ORDER BY severity",
            (cve_id.upper(),),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def has_nuclei_template(self, cve_id: str) -> bool:
        """Check if a CVE has a Nuclei validation template available."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM nuclei_templates WHERE cve_id = ? LIMIT 1", (cve_id.upper(),))
        result = cursor.fetchone()
        conn.close()
        return result is not None

    # =========================================================================
    # NVD CVE Lookup Methods
    # =========================================================================

    def get_nvd_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get NVD CVE data from local database.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            Dict with CVE data if found, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM nvd_cves WHERE cve_id = ?", (cve_id.upper(),))
            row = cursor.fetchone()
            if row:
                return {
                    "cve_id": row["cve_id"],
                    "description": row["description"],
                    "severity": row["severity"],
                    "cvss_score": row["cvss_score"],
                    "cvss_vector": row["cvss_vector"],
                    "cwe_ids": json.loads(row["cwe_ids"] or "[]"),
                    "affected_packages": json.loads(row["affected_packages"] or "[]"),
                    "references": json.loads(row["references_json"] or "[]"),
                    "published": row["published"],
                    "modified": row["modified"],
                    "source_identifier": row["source_identifier"],
                    "updated_at": row["updated_at"],
                }
            return None
        finally:
            conn.close()

    def get_recent_nvd_cves(
        self,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get recent NVD CVEs from local database.

        Args:
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            limit: Max results
            offset: Pagination offset

        Returns:
            List of CVE dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            query = "SELECT * FROM nvd_cves"
            params: list = []

            if severity:
                query += " WHERE severity = ?"
                params.append(severity.upper())

            query += " ORDER BY published DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            rows = cursor.fetchall()

            return [
                {
                    "cve_id": r["cve_id"],
                    "description": r["description"],
                    "severity": r["severity"],
                    "cvss_score": r["cvss_score"],
                    "cvss_vector": r["cvss_vector"],
                    "cwe_ids": json.loads(r["cwe_ids"] or "[]"),
                    "affected_packages": json.loads(r["affected_packages"] or "[]"),
                    "published": r["published"],
                    "modified": r["modified"],
                }
                for r in rows
            ]
        finally:
            conn.close()

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
            # Security: table names are defined as a hardcoded allowlist here —
            # never interpolate user-supplied table names into SQL.
            _ALLOWED_STAT_TABLES = frozenset({
                "epss_scores", "kev_entries", "exploit_intelligence",
                "threat_actor_mappings", "supply_chain_vulns",
                "cloud_security_bulletins", "early_signals",
                "national_cert_advisories", "exploit_confidence_scores",
                "geo_weighted_risks",
            })
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
                # Allowlist check prevents any future code paths from injecting
                # attacker-controlled table names into this query.
                if table not in _ALLOWED_STAT_TABLES:
                    raise ValueError(f"Disallowed table name in stats query: {table!r}")
                try:
                    cursor.execute(f"SELECT COUNT(*) as count FROM {table}")  # nosec B608 — allowlisted above
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

                # SSVC decision intelligence (Vulnrichment)
                ssvc = self.get_vulnrichment(cve_id)
                if ssvc:
                    enriched_finding["ssvc_action"] = ssvc.get("ssvc_action", "")
                    enriched_finding["ssvc_exploitation"] = ssvc.get("ssvc_exploitation", "")
                    enriched_finding["ssvc_automatable"] = ssvc.get("ssvc_automatable", "")
                    enriched_finding["ssvc_technical_impact"] = ssvc.get("ssvc_technical_impact", "")

                # PoC availability
                enriched_finding["has_public_poc"] = self.has_public_exploit(cve_id)
                poc_list = self.get_poc_for_cve(cve_id)
                if poc_list:
                    enriched_finding["poc_count"] = len(poc_list)
                    enriched_finding["top_poc_url"] = poc_list[0].get("repo_url", "")

                # Exploitation in the wild
                enriched_finding["exploited_in_wild"] = self.is_exploited_in_wild(cve_id)

                # Nuclei template availability
                enriched_finding["has_nuclei_template"] = self.has_nuclei_template(cve_id)
                nuclei = self.get_nuclei_templates(cve_id)
                if nuclei:
                    enriched_finding["nuclei_template_url"] = nuclei[0].get("template_url", "")

            enriched.append(enriched_finding)

        return enriched

    @staticmethod
    async def scheduler(
        settings: Any, interval_hours: int = 24
    ) -> None:  # pragma: no cover - background task
        """Background scheduler for periodic feed refresh.

        Refreshes all primary feeds: EPSS, KEV, NVD, ExploitDB, OSV, GitHub Advisories.

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

        def _refresh_all() -> None:
            """Run all feed refreshes with error isolation."""
            feeds = [
                ("EPSS", service.refresh_epss),
                ("KEV", service.refresh_kev),
                ("VEDAS", service.refresh_vedas),
                ("NVD", lambda: service.refresh_nvd(days=7)),
                ("ExploitDB", service.refresh_exploitdb),
                ("OSV", service.refresh_osv),
                ("GitHub Advisories", service.refresh_github_advisories),
                ("Vulnrichment (SSVC)", service.refresh_vulnrichment),
                ("PoC-in-GitHub", service.refresh_poc_in_github),
                ("InTheWild", service.refresh_inthewild),
                ("Nuclei Templates", service.refresh_nuclei_templates),
                ("AlienVault OTX", service.refresh_otx),
                ("URLhaus", service.refresh_urlhaus),
            ]
            for name, refresh_fn in feeds:
                try:
                    result = refresh_fn()
                    if result.success:
                        logger.info(
                            "%s refresh OK: %d records", name, result.records_updated
                        )
                    else:
                        logger.warning("%s refresh failed: %s", name, result.error)
                except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                    logger.error("%s refresh error: %s", name, exc)

        # Initial refresh on startup
        logger.info("Starting initial feed refresh (all 11 feeds)")
        _refresh_all()

        while True:
            await asyncio.sleep(delay)
            logger.info(
                "Running scheduled feed refresh (interval: %dh)", interval_hours
            )
            _refresh_all()


    def refresh_otx(self) -> "FeedRefreshResult":
        """Fetch threat pulses from AlienVault OTX.

        Requires OTX_API_KEY environment variable.
        Returns FeedRefreshResult with pulse count or skips gracefully when key absent.
        """
        api_key = os.environ.get("OTX_API_KEY", "")
        if not api_key:
            logger.info("OTX: OTX_API_KEY not set — skipping AlienVault OTX feed")
            return FeedRefreshResult(
                feed_name="otx",
                success=True,
                records_updated=0,
                error="OTX_API_KEY not configured",
            )

        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {"X-OTX-API-KEY": api_key}
        all_pulses: list = []
        page = 1

        try:
            while True:
                resp = requests.get(
                    url,
                    headers=headers,
                    params={"page": page, "limit": 50},
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                results = data.get("results", [])
                if not results:
                    break
                all_pulses.extend(results)
                if not data.get("next"):
                    break
                page += 1
                if page > 20:  # cap at 1000 pulses
                    break

            # Persist pulse IOCs into threat_actor_mappings table
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            inserted = 0
            for pulse in all_pulses:
                pulse_name = pulse.get("name", "")
                for ioc in pulse.get("indicators", []):
                    cve_refs = [
                        t for t in pulse.get("tags", []) if t.upper().startswith("CVE-")
                    ]
                    cve_id = cve_refs[0] if cve_refs else f"OTX-{pulse.get('id', 'unknown')}"
                    try:
                        cursor.execute(
                            """INSERT OR IGNORE INTO threat_actor_mappings
                               (cve_id, threat_actor, campaign, confidence, source, created_at)
                               VALUES (?, ?, ?, ?, ?, ?)""",
                            (
                                cve_id,
                                pulse.get("author_name", "OTX"),
                                pulse_name,
                                "medium",
                                "alienvault_otx",
                                now,
                            ),
                        )
                        inserted += cursor.rowcount
                    except (ValueError, TypeError, KeyError, sqlite3.DatabaseError) as _row_exc:
                        logger.debug("OTX: skipped malformed row: %s", _row_exc)
            conn.commit()
            conn.close()

            logger.info("OTX: fetched %d pulses, %d IOC mappings stored", len(all_pulses), inserted)
            return FeedRefreshResult(
                feed_name="otx",
                success=True,
                records_updated=inserted,
            )

        except RequestException as exc:
            error_msg = f"OTX feed fetch failed: {exc}"
            logger.warning(error_msg)
            return FeedRefreshResult(
                feed_name="otx", success=False, records_updated=0, error=error_msg
            )

    def refresh_urlhaus(self) -> "FeedRefreshResult":
        """Fetch malicious URL indicators from abuse.ch URLhaus.

        No API key required — free public JSON feed.
        Stores URL indicators into supply_chain_vulns table as threat markers.
        """
        url = "https://urlhaus.abuse.ch/downloads/json/"
        try:
            resp = requests.get(url, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except RequestException as exc:
            error_msg = f"URLhaus feed fetch failed: {exc}"
            logger.warning(error_msg)
            return FeedRefreshResult(
                feed_name="urlhaus", success=False, records_updated=0, error=error_msg
            )
        except (ValueError, KeyError) as exc:
            error_msg = f"URLhaus feed parse failed: {exc}"
            logger.warning(error_msg)
            return FeedRefreshResult(
                feed_name="urlhaus", success=False, records_updated=0, error=error_msg
            )

        urls = data.get("urls", [])
        if not urls:
            logger.info("URLhaus: no URL entries in feed response")
            return FeedRefreshResult(feed_name="urlhaus", success=True, records_updated=0)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()

        # Store in exploit_intelligence table as malicious URL indicators
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS urlhaus_indicators (
               url_id TEXT PRIMARY KEY,
               url TEXT NOT NULL,
               url_status TEXT,
               threat TEXT,
               tags TEXT,
               host TEXT,
               date_added TEXT,
               updated_at TEXT NOT NULL
            )"""
        )

        inserted = 0
        for entry in urls[:5000]:  # cap at 5k entries
            url_id = str(entry.get("id", ""))
            if not url_id:
                continue
            try:
                cursor.execute(
                    """INSERT OR REPLACE INTO urlhaus_indicators
                       (url_id, url, url_status, threat, tags, host, date_added, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        url_id,
                        entry.get("url", "")[:2048],
                        entry.get("url_status", ""),
                        entry.get("threat", ""),
                        ",".join(entry.get("tags", []) or []),
                        entry.get("host", ""),
                        entry.get("date_added", ""),
                        now,
                    ),
                )
                inserted += cursor.rowcount
            except (ValueError, TypeError, KeyError, sqlite3.DatabaseError) as _row_exc:
                logger.debug("URLhaus: skipped malformed row: %s", _row_exc)

        cursor.execute(
            """INSERT OR REPLACE INTO feed_metadata
               (feed_name, last_refresh, records_count, status)
               VALUES (?, ?, ?, ?)""",
            ("urlhaus", now, inserted, "success"),
        )
        conn.commit()
        conn.close()

        logger.info("URLhaus: %d malicious URL indicators stored", inserted)
        return FeedRefreshResult(
            feed_name="urlhaus",
            success=True,
            records_updated=inserted,
        )

    def get_feed_config(self) -> dict:
        """Return which feeds are configured/active based on env vars.

        Used by the /api/v1/feeds/config endpoint.
        """
        nvd_key = os.environ.get("NVD_API_KEY", "")
        otx_key = os.environ.get("OTX_API_KEY", "")
        abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        github_token = os.environ.get("FIXOPS_GITHUB_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")

        def _masked(key: str) -> str:
            return f"{key[:4]}...{key[-4:]}" if len(key) >= 8 else ("set" if key else "")

        return {
            "feeds": {
                "nvd": {
                    "name": "NVD (National Vulnerability Database)",
                    "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    "status": "authenticated" if nvd_key else "unauthenticated",
                    "api_key_configured": bool(nvd_key),
                    "api_key_env": "NVD_API_KEY",
                    "api_key_hint": _masked(nvd_key),
                    "rate_limit": "50 req/30s" if nvd_key else "5 req/30s",
                    "register_url": "https://nvd.nist.gov/developers/request-an-api-key",
                    "notes": "Free API key gives 10x higher rate limit. Recommended.",
                },
                "epss": {
                    "name": "EPSS (Exploit Prediction Scoring System)",
                    "url": "https://epss.cyentia.com/epss_scores-current.csv.gz",
                    "status": "active",
                    "api_key_configured": False,
                    "notes": "No API key required. Free public data from FIRST.org.",
                },
                "cisa_kev": {
                    "name": "CISA Known Exploited Vulnerabilities",
                    "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    "status": "active",
                    "api_key_configured": False,
                    "notes": "No API key required. Official CISA catalog.",
                },
                "alienvault_otx": {
                    "name": "AlienVault OTX",
                    "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
                    "status": "active" if otx_key else "inactive",
                    "api_key_configured": bool(otx_key),
                    "api_key_env": "OTX_API_KEY",
                    "api_key_hint": _masked(otx_key),
                    "register_url": "https://otx.alienvault.com/api",
                    "notes": "Free account required at otx.alienvault.com.",
                },
                "urlhaus": {
                    "name": "abuse.ch URLhaus",
                    "url": "https://urlhaus.abuse.ch/downloads/json/",
                    "status": "active",
                    "api_key_configured": False,
                    "notes": "No API key required. Free malicious URL feed.",
                },
                "abuseipdb": {
                    "name": "AbuseIPDB",
                    "url": "https://api.abuseipdb.com/api/v2/check",
                    "status": "active" if abuseipdb_key else "inactive",
                    "api_key_configured": bool(abuseipdb_key),
                    "api_key_env": "ABUSEIPDB_API_KEY",
                    "api_key_hint": _masked(abuseipdb_key),
                    "rate_limit": "1000 checks/day (free tier)",
                    "register_url": "https://www.abuseipdb.com/register",
                    "notes": "Free tier: 1K checks/day. Used for IP reputation lookup.",
                },
                "feodo_tracker": {
                    "name": "Feodo Tracker (abuse.ch C2 blocklist)",
                    "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                    "status": "active",
                    "api_key_configured": False,
                    "notes": "No API key required. Free C2 IP blocklist from abuse.ch.",
                },
                "github_advisory": {
                    "name": "GitHub Security Advisories",
                    "url": "https://api.github.com/advisories",
                    "status": "authenticated" if github_token else "unauthenticated",
                    "api_key_configured": bool(github_token),
                    "api_key_env": "FIXOPS_GITHUB_TOKEN",
                    "api_key_hint": _masked(github_token),
                    "rate_limit": "5000 req/hr authenticated vs 60 req/hr unauthenticated",
                    "notes": "Personal access token or GitHub App token.",
                },
                "osv": {
                    "name": "OSV (Open Source Vulnerabilities)",
                    "url": "https://api.osv.dev/v1/querybatch",
                    "status": "active",
                    "api_key_configured": False,
                    "notes": "No API key required. Google OSV.dev free API.",
                },
            },
            "summary": {
                "total_feeds": 9,
                "active_feeds": sum(
                    1 for f in ["nvd", "epss", "cisa_kev", "urlhaus", "feodo_tracker", "osv"]
                    + (["alienvault_otx"] if otx_key else [])
                    + (["abuseipdb"] if abuseipdb_key else [])
                    + (["github_advisory"] if github_token else [])
                    if True
                ),
                "keys_configured": {
                    "NVD_API_KEY": bool(nvd_key),
                    "OTX_API_KEY": bool(otx_key),
                    "ABUSEIPDB_API_KEY": bool(abuseipdb_key),
                    "FIXOPS_GITHUB_TOKEN": bool(github_token),
                },
            },
        }


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
