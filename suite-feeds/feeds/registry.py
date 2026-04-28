"""Global Feed Registry — unified catalog for all threat-intel importers.

A single source of truth that lists every feed the platform consumes, their
metadata (source URL, license, refresh interval), and their last import
status (imported_at, entry count, ok/error).

Usage:
    from feeds.registry import (
        list_feeds, get_feed, refresh_feed, registered_feed_ids,
    )

DB: data/feed_registry.db (PersistentDict pattern)

Adding a new feed: append a `_register(...)` call inside `_discover()` —
keep importer module imports inside that function so an ImportError in one
feed module does not crash the registry as a whole.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Persistent state (last_imported_at / last_entry_count / last_status)
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[2]  # suite-feeds/feeds/registry.py -> project root
_DEFAULT_DB = str(_PROJECT_ROOT / "data" / "feed_registry.db")

_state_lock = threading.Lock()
_state_store = None  # type: ignore[var-annotated]


def _get_state_store(db_path: Optional[str] = None):
    """Return a PersistentDict-backed state store.

    Falls back to a plain in-memory dict when PersistentDict cannot be
    imported (e.g. tests or stripped environments).
    """
    global _state_store
    if _state_store is not None and db_path is None:
        return _state_store

    path = db_path or _DEFAULT_DB
    try:
        import sys
        suite_core = str(_PROJECT_ROOT / "suite-core")
        if suite_core not in sys.path:
            sys.path.insert(0, suite_core)
        from core.persistent_store import PersistentDict
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        store = PersistentDict("feed_registry_state", db_path=path)
    except Exception as exc:  # noqa: BLE001 — defensive: never crash registry
        logger.warning("feed_registry: PersistentDict unavailable, using in-memory: %s", exc)
        store = {}

    if db_path is None:
        _state_store = store
    return store


# ---------------------------------------------------------------------------
# Feed definition
# ---------------------------------------------------------------------------

@dataclass
class FeedDefinition:
    """Static metadata for a registered feed."""

    id: str  # slug (e.g. "cisa_kev")
    display_name: str
    source_url: str
    source_type: str  # one of: json, xml, csv, yaml, stix
    license: str
    refresh_interval_seconds: int
    importer_callable: Callable[[], Dict[str, Any]] = field(repr=False)
    count_callable: Optional[Callable[[], int]] = field(default=None, repr=False)
    description: str = ""


# ---------------------------------------------------------------------------
# Discovery — populate _FEEDS by importing each feed module
# ---------------------------------------------------------------------------

_FEEDS: Dict[str, FeedDefinition] = {}
_discovery_lock = threading.Lock()
_discovery_done = False


def _register(feed: FeedDefinition) -> None:
    if feed.id in _FEEDS:
        logger.warning("feed_registry: duplicate registration for %r — skipping", feed.id)
        return
    _FEEDS[feed.id] = feed


def _discover() -> None:
    """Walk the importer modules and register a FeedDefinition for each.

    Each importer is loaded inside its own try/except so an unrelated
    ImportError in one module never crashes the registry as a whole.
    """
    # ---------- CISA KEV ----------
    try:
        from feeds.cisa_kev.importer import CisaKevImporter, CISA_KEV_URL

        def _refresh_cisa_kev() -> Dict[str, Any]:
            imp = CisaKevImporter()
            return imp.run(idempotent=True)

        def _count_cisa_kev() -> int:
            try:
                return CisaKevImporter().total_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="cisa_kev",
            display_name="CISA Known Exploited Vulnerabilities",
            source_url=CISA_KEV_URL,
            source_type="json",
            license="CC0-1.0 (US Government work)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_cisa_kev,
            count_callable=_count_cisa_kev,
            description="CISA's authoritative catalog of CVEs known to be exploited in the wild.",
        ))
    except ImportError as exc:
        logger.warning("feed_registry: cisa_kev importer unavailable: %s", exc)

    # ---------- MITRE ATT&CK ----------
    try:
        from feeds.mitre_attack.extractor import (
            MitreAttackExtractor,
            STIX_BUNDLE_URL,
            _DEFAULT_DB as _MITRE_DB,
        )

        def _refresh_mitre() -> Dict[str, Any]:
            return MitreAttackExtractor().run()

        def _count_mitre() -> int:
            try:
                store = MitreAttackExtractor(_MITRE_DB).get_store()
                rows = store.all()
                store.close()
                return len(rows)
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="mitre_attack",
            display_name="MITRE ATT&CK Enterprise",
            source_url=STIX_BUNDLE_URL,
            source_type="stix",
            license="Apache-2.0",
            refresh_interval_seconds=604_800,  # weekly
            importer_callable=_refresh_mitre,
            count_callable=_count_mitre,
            description="MITRE ATT&CK enterprise STIX 2.1 bundle — techniques, sub-techniques, and tactics.",
        ))
    except ImportError as exc:
        logger.warning("feed_registry: mitre_attack importer unavailable: %s", exc)

    # ---------- NIST NVD CVE ----------
    try:
        from feeds.nvd_cve.importer import NvdCveImporter, NVD_CVE_URL

        def _refresh_nvd_cve() -> Dict[str, Any]:
            return NvdCveImporter().run(days=7)

        def _count_nvd_cve() -> int:
            try:
                return NvdCveImporter().total_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="nvd_cve",
            display_name="NIST NVD CVE Feed",
            source_url=NVD_CVE_URL,
            source_type="json",
            license="Public Domain (US Government work)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_nvd_cve,
            count_callable=_count_nvd_cve,
            description="NIST National Vulnerability Database — authoritative CVE catalog with CVSS v3.1 metrics and CWE weaknesses.",
        ))
    except ImportError as exc:
        logger.warning("feed_registry: nvd_cve importer unavailable: %s", exc)

    # ---------- SigmaHQ ----------
    try:
        from feeds.sigmahq.importer import (
            run_import as _sigma_run,
            get_store_stats as _sigma_stats,
            SIGMAHQ_TAR_URL,
        )

        def _refresh_sigma() -> Dict[str, Any]:
            return _sigma_run()

        def _count_sigma() -> int:
            try:
                return int(_sigma_stats().get("total", 0))
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="sigmahq",
            display_name="SigmaHQ Detection Rules",
            source_url=SIGMAHQ_TAR_URL,
            source_type="yaml",
            license="DRL-1.1 (Detection Rule License)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_sigma,
            count_callable=_count_sigma,
            description="Open-source generic detection rule format — Sigma — covering SIEM/EDR.",
        ))
    except ImportError as exc:
        logger.warning("feed_registry: sigmahq importer unavailable: %s", exc)

    # ---------- OSV (Open Source Vulnerabilities) ----------
    try:
        from feeds.osv.importer import (
            run_import as _osv_run,
            get_store_stats as _osv_stats,
            DEFAULT_ECOSYSTEM as _OSV_DEFAULT_ECO,
            OSV_BUCKET_BASE as _OSV_BASE,
        )

        def _refresh_osv() -> Dict[str, Any]:
            return _osv_run(ecosystem=_OSV_DEFAULT_ECO)

        def _count_osv() -> int:
            try:
                return int(_osv_stats().get("total", 0))
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="osv",
            display_name="OSV (Open Source Vulnerabilities)",
            source_url=f"{_OSV_BASE}/{_OSV_DEFAULT_ECO}/all.zip",
            source_type="json",
            license="CC-BY-4.0",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_osv,
            count_callable=_count_osv,
            description=(
                "Google-run open vulnerability database aggregating PyPI, npm, "
                "Maven, Go, RubyGems, NuGet, crates.io, Packagist, and Hex "
                "advisories under the OSV schema."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: osv importer unavailable: %s", exc)

    # ---------- AbuseIPDB / EmergingThreats ----------
    try:
        from feeds.abuseipdb.importer import (
            run_import as _abuseipdb_run,
            total_count as _abuseipdb_count,
            ET_COMPROMISED_IPS_URL,
        )

        def _refresh_abuseipdb() -> Dict[str, Any]:
            return _abuseipdb_run()

        def _count_abuseipdb() -> int:
            try:
                return _abuseipdb_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="abuseipdb",
            display_name="AbuseIPDB / EmergingThreats Compromised IPs",
            source_url=ET_COMPROMISED_IPS_URL,
            source_type="csv",
            license="BSD-style (ET Open Ruleset); AbuseIPDB API ToS when key set",
            refresh_interval_seconds=21_600,  # 6h — the ET list updates frequently
            importer_callable=_refresh_abuseipdb,
            count_callable=_count_abuseipdb,
            description=(
                "Unified IP blocklist — Emerging Threats compromised-ips.txt "
                "(public, no API key) plus AbuseIPDB top-10K blacklist when "
                "ABUSEIPDB_API_KEY env is set."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: abuseipdb importer unavailable: %s", exc)

    # ---------- Spamhaus DROP / EDROP ----------
    try:
        from feeds.spamhaus_drop.importer import (
            run_import as _spamhaus_run,
            get_store_stats as _spamhaus_stats,
            DROP_URL as _SPAMHAUS_DROP_URL,
        )

        def _refresh_spamhaus() -> Dict[str, Any]:
            return _spamhaus_run()

        def _count_spamhaus() -> int:
            try:
                return int(_spamhaus_stats().get("total", 0))
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="spamhaus_drop",
            display_name="Spamhaus DROP / EDROP Blocklists",
            source_url=_SPAMHAUS_DROP_URL,
            source_type="txt",
            license="Spamhaus Terms of Service (free for non-commercial use)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_spamhaus,
            count_callable=_count_spamhaus,
            description=(
                "Spamhaus Don't Route Or Peer (DROP) and Extended DROP (EDROP) "
                "CIDR blocklists. Public feeds listing netblocks that are hijacked, "
                "leased to spammers, or otherwise controlled by cyber-criminals."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: spamhaus_drop importer unavailable: %s", exc)

    # ---------- EPSS ----------
    try:
        from feeds.epss.importer import EpssImporter, EPSS_URL

        def _refresh_epss() -> Dict[str, Any]:
            return EpssImporter().run()

        def _count_epss() -> int:
            try:
                return EpssImporter().total_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="epss",
            display_name="FIRST.org EPSS (Exploit Prediction Scoring System)",
            source_url=EPSS_URL,
            source_type="csv",
            license="CC-BY-4.0 (FIRST.org)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_epss,
            count_callable=_count_epss,
            description="ML-derived probability (0..1) that each CVE will be exploited in the next 30 days.",
        ))
    except ImportError as exc:
        logger.warning("feed_registry: epss importer unavailable: %s", exc)

    # ---------- AlienVault OTX (Open Threat Exchange) ----------
    try:
        from feeds.otx.importer import (
            run_import as _otx_run,
            get_store_stats as _otx_stats,
            OTX_PUBLIC_ACTIVITY_URL as _OTX_URL,
        )

        def _refresh_otx() -> Dict[str, Any]:
            return _otx_run()

        def _count_otx() -> int:
            try:
                return int(_otx_stats().get("total_pulses", 0))
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="otx",
            display_name="AlienVault OTX (Open Threat Exchange)",
            source_url=_OTX_URL,
            source_type="json",
            license="Open (free tier; per-pulse author license varies)",
            refresh_interval_seconds=3_600,  # hourly
            importer_callable=_refresh_otx,
            count_callable=_count_otx,
            description=(
                "AlienVault OTX threat-intel pulses with flattened indicators "
                "(IPv4/IPv6/domain/URL/file hashes/CVE) and MITRE ATT&CK "
                "technique cross-links. Defaults to the public activity feed; "
                "uses the subscribed feed when OTX_API_KEY is set."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: otx importer unavailable: %s", exc)

    # ---------- Tor Exit Nodes ----------
    try:
        from feeds.tor_exit_nodes.importer import (
            run_import as _tor_run,
            total_count as _tor_count,
            TOR_BULK_EXIT_LIST_URL,
        )

        def _refresh_tor() -> Dict[str, Any]:
            return _tor_run()

        def _count_tor() -> int:
            try:
                return _tor_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="tor_exit_nodes",
            display_name="Tor Exit Node List (TorProject)",
            source_url=TOR_BULK_EXIT_LIST_URL,
            source_type="txt",
            license="Public Domain (TorProject)",
            refresh_interval_seconds=1_800,  # 30 min — matches upstream refresh rate
            importer_callable=_refresh_tor,
            count_callable=_count_tor,
            description=(
                "TorProject bulk exit-node list — one IPv4/IPv6 per line. "
                "Replace semantics: each import is a full replacement of the "
                "live exit-node set. Used for Tor egress detection in ALDECI."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: tor_exit_nodes importer unavailable: %s", exc)

    # ---------- Nuclei Templates ----------
    try:
        from feeds.nuclei_templates.importer import (
            run_import as _nuclei_run,
            get_store_stats as _nuclei_stats,
            NUCLEI_TAR_URL,
        )

        def _refresh_nuclei() -> Dict[str, Any]:
            return _nuclei_run()

        def _count_nuclei() -> int:
            try:
                return int(_nuclei_stats().get("total", 0))
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="nuclei_templates",
            display_name="ProjectDiscovery Nuclei Templates",
            source_url=NUCLEI_TAR_URL,
            source_type="yaml",
            license="MIT (ProjectDiscovery)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_nuclei,
            count_callable=_count_nuclei,
            description=(
                "ProjectDiscovery Nuclei detection templates — ~9000 YAML templates "
                "covering CVEs, misconfigurations, exposures, and vulnerabilities, "
                "with severity, CVE/CWE classification, and tag metadata."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: nuclei_templates importer unavailable: %s", exc)

    # ---------- ExploitDB ----------
    try:
        from feeds.exploitdb.importer import (
            run_import as _exploitdb_run,
            get_store_stats as _exploitdb_stats,
            EXPLOITDB_CSV_URL,
        )

        def _refresh_exploitdb() -> Dict[str, Any]:
            return _exploitdb_run()

        def _count_exploitdb() -> int:
            try:
                return int(_exploitdb_stats().get("total", 0))
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="exploitdb",
            display_name="ExploitDB (Offensive Security Exploit Database)",
            source_url=EXPLOITDB_CSV_URL,
            source_type="csv",
            license="GPL-2.0 (Offensive Security)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_exploitdb,
            count_callable=_count_exploitdb,
            description=(
                "Offensive Security's public Exploit Database. The master CSV "
                "indexes every published PoC with metadata (type, platform, "
                "author, port, dates) and CVE cross-references."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: exploitdb importer unavailable: %s", exc)



    # ---------- SANS ISC ----------
    try:
        from feeds.sans_isc.importer import (
            run_import as _sans_isc_run,
            total_source_count as _sans_isc_src_count,
            SANS_SOURCES_URL as _SANS_SOURCES_URL,
        )

        def _refresh_sans_isc() -> Dict[str, Any]:
            return _sans_isc_run()

        def _count_sans_isc() -> int:
            try:
                return _sans_isc_src_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="sans_isc",
            display_name="SANS Internet Storm Center Top Sources",
            source_url=_SANS_SOURCES_URL,
            source_type="json",
            license="Public (SANS ISC — free, no API key required)",
            refresh_interval_seconds=3_600,  # hourly
            importer_callable=_refresh_sans_isc,
            count_callable=_count_sans_isc,
            description=(
                "SANS Internet Storm Center top 100 attack source IPs with "
                "country, attack count, and first/last seen dates; plus top "
                "attacked ports with service name and attack count."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: sans_isc importer unavailable: %s", exc)

    # ---------- Security Blogs RSS ----------
    try:
        from feeds.security_blogs.importer import (
            run_import as _security_blogs_run,
            total_count as _security_blogs_count,
            SOURCES_URL as _SECURITY_BLOGS_URL,
        )

        def _refresh_security_blogs() -> Dict[str, Any]:
            return _security_blogs_run()

        def _count_security_blogs() -> int:
            try:
                return _security_blogs_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="security_blogs",
            display_name="Security Blog RSS Aggregator",
            source_url=_SECURITY_BLOGS_URL,
            source_type="xml",
            license="Public (no API key required; per-blog copyright applies)",
            refresh_interval_seconds=3_600,  # hourly
            importer_callable=_refresh_security_blogs,
            count_callable=_count_security_blogs,
            description=(
                "Aggregated RSS/Atom posts from canonical security blogs: "
                "Krebs on Security, The Hacker News, BleepingComputer, "
                "Dark Reading, Schneier on Security, SecurityWeek, "
                "Microsoft MSRC, Google Project Zero, NCSC UK."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: security_blogs importer unavailable: %s", exc)


    # ---------- URLscan.io ----------
    try:
        from feeds.urlscan.importer import (
            run_import as _urlscan_run,
            get_store_stats as _urlscan_stats,
            total_count as _urlscan_count,
            URLSCAN_SEARCH_URL as _URLSCAN_URL,
            DEFAULT_QUERY as _URLSCAN_DEFAULT_QUERY,
        )

        def _refresh_urlscan() -> Dict[str, Any]:
            return _urlscan_run(query=_URLSCAN_DEFAULT_QUERY)

        def _count_urlscan() -> int:
            try:
                return _urlscan_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="urlscan",
            display_name="URLscan.io Public Scan Feed",
            source_url=_URLSCAN_URL,
            source_type="json",
            license="Public (no auth required; URLSCAN_API_KEY unlocks higher rate limits)",
            refresh_interval_seconds=3_600,  # hourly
            importer_callable=_refresh_urlscan,
            count_callable=_count_urlscan,
            description=(
                "URLscan.io public scan results — URL, domain, country, scan method, "
                "tags, and overall malicious verdict/score. Defaults to "
                "task.tags:phishing query; URLSCAN_API_KEY env var unlocks "
                "higher rate limits."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: urlscan importer unavailable: %s", exc)

    # ---------- GreyNoise Community ----------
    try:
        from feeds.greynoise.importer import (
            bulk_import as _greynoise_bulk,
            get_store_stats as _greynoise_stats,
            GREYNOISE_COMMUNITY_URL as _GREYNOISE_URL,
        )

        def _refresh_greynoise() -> Dict[str, Any]:
            # No-op bulk import with empty list — registry refresh just returns stats.
            # Real lookups are done on-demand via the API endpoint.
            return _greynoise_stats()

        def _count_greynoise() -> int:
            try:
                return int(_greynoise_stats().get("total", 0))
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="greynoise",
            display_name="GreyNoise Community IP Intelligence",
            source_url=_GREYNOISE_URL.replace("{ip}", "<ip>"),
            source_type="json",
            license="GreyNoise Community API Terms of Service (free tier, no key required)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_greynoise,
            count_callable=_count_greynoise,
            description=(
                "GreyNoise community IP classification — benign / malicious / unknown. "
                "Per-IP lookup with 1-day cache. GREYNOISE_API_KEY env var unlocks "
                "the paid tier and removes rate limits."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: greynoise importer unavailable: %s", exc)

    # ---------- SecurityTrails Passive DNS ----------
    try:
        from feeds.securitytrails.importer import (
            run_import as _securitytrails_run,
            get_store_stats as _securitytrails_stats,
            total_count as _securitytrails_count,
            SECURITYTRAILS_BASE_URL as _ST_BASE_URL,
        )

        def _refresh_securitytrails() -> Dict[str, Any]:
            # Registry-level refresh is a no-op stats call; real enumeration
            # is triggered per-domain via POST /api/v1/securitytrails/enumerate.
            return _securitytrails_stats()

        def _count_securitytrails() -> int:
            try:
                return _securitytrails_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="securitytrails",
            display_name="SecurityTrails Passive DNS",
            source_url=_ST_BASE_URL,
            source_type="json",
            license="SecurityTrails API Terms of Service (free tier: 50 calls/month; SECURITYTRAILS_API_KEY required)",
            refresh_interval_seconds=604_800,  # 7 days — subdomain data is stable
            importer_callable=_refresh_securitytrails,
            count_callable=_count_securitytrails,
            description=(
                "SecurityTrails passive DNS feed — subdomain enumeration, "
                "A-record history (ip, first_seen, last_seen), and reverse DNS "
                "lookups. Requires SECURITYTRAILS_API_KEY env var. "
                "Free tier: 50 API calls/month. Results cached 7 days."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: securitytrails importer unavailable: %s", exc)

    # ---------- Censys CVE Host Search ----------
    try:
        from feeds.censys.importer import (
            run_import as _censys_run,
            get_store_stats as _censys_stats,
            total_count as _censys_count,
            CENSYS_SEARCH_URL as _CENSYS_URL,
        )

        def _refresh_censys() -> Dict[str, Any]:
            # Registry-level refresh is a no-op stats call; real CVE searches
            # are triggered on-demand via POST /api/v1/censys/search.
            return _censys_stats()

        def _count_censys() -> int:
            try:
                return _censys_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="censys",
            display_name="Censys CVE Host Search",
            source_url=_CENSYS_URL,
            source_type="json",
            license="Censys Search API Terms of Service (community tier free with registration; CENSYS_API_ID + CENSYS_API_SECRET required)",
            refresh_interval_seconds=86_400,  # 1 day per CVE query
            importer_callable=_refresh_censys,
            count_callable=_count_censys,
            description=(
                "Censys Search API v2 — find hosts exposed on the internet that are "
                "vulnerable to a given CVE. Returns IP, services, location, ASN, and "
                "cve_ids. Requires CENSYS_API_ID and CENSYS_API_SECRET env vars "
                "(community tier free at https://search.censys.io/account). "
                "Results cached 1 day per CVE query."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: censys importer unavailable: %s", exc)

    # ---------- HIBP (Have I Been Pwned) ----------
    try:
        from feeds.hibp.importer import HibpImporter, HIBP_BREACHES_URL  # noqa: PLC0415

        def _refresh_hibp() -> Dict[str, Any]:
            return HibpImporter().import_breaches(idempotent=True)

        def _count_hibp() -> int:
            try:
                return HibpImporter().total_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="hibp",
            display_name="Have I Been Pwned — Breach Catalog",
            source_url=HIBP_BREACHES_URL,
            source_type="json",
            license="Have I Been Pwned API Terms (free breach catalog; paid account-check requires HIBP_API_KEY)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_hibp,
            count_callable=_count_hibp,
            description=(
                "Have I Been Pwned breach catalog (~700 entries, free). "
                "Password range proxy uses k-anonymity (5-char SHA-1 prefix only — full hash never sent). "
                "Breached-account check requires HIBP_API_KEY env var (paid tier). "
                "Privacy: full passwords and email addresses are never logged or stored."
            ),
        ))
    except ImportError as exc:
        logger.warning("feed_registry: hibp importer unavailable: %s", exc)


def _ensure_discovered() -> None:
    global _discovery_done
    with _discovery_lock:
        if _discovery_done:
            return
        _discover()
        _discovery_done = True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def registered_feed_ids() -> List[str]:
    """Return all registered feed IDs (sorted)."""
    _ensure_discovered()
    return sorted(_FEEDS.keys())


def _to_dict(feed: FeedDefinition, store: Any) -> Dict[str, Any]:
    """Combine static metadata + last-run state into a single dict."""
    state: Dict[str, Any] = {}
    try:
        if hasattr(store, "get"):
            state = store.get(feed.id, {}) or {}
        elif feed.id in store:
            state = store[feed.id]
    except Exception:  # noqa: BLE001
        state = {}

    entry_count = state.get("last_entry_count")
    if entry_count is None and feed.count_callable is not None:
        try:
            entry_count = feed.count_callable()
        except Exception:  # noqa: BLE001
            entry_count = None

    return {
        "id": feed.id,
        "display_name": feed.display_name,
        "source_url": feed.source_url,
        "source_type": feed.source_type,
        "license": feed.license,
        "refresh_interval_seconds": feed.refresh_interval_seconds,
        "description": feed.description,
        "last_imported_at": state.get("last_imported_at"),
        "last_entry_count": entry_count,
        "last_status": state.get("last_status", "unknown"),
        "last_error": state.get("last_error"),
        "last_result": state.get("last_result"),
    }


def list_feeds(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all registered feeds with their last-run state."""
    _ensure_discovered()
    store = _get_state_store(db_path)
    return [_to_dict(_FEEDS[fid], store) for fid in sorted(_FEEDS.keys())]


def get_feed(feed_id: str, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return a single feed's metadata + state. Raises KeyError if unknown."""
    _ensure_discovered()
    if feed_id not in _FEEDS:
        raise KeyError(feed_id)
    store = _get_state_store(db_path)
    return _to_dict(_FEEDS[feed_id], store)


def refresh_feed(feed_id: str, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Trigger the importer for *feed_id*, persist last-run state, return result.

    Raises:
        KeyError: feed_id is not registered.
    """
    _ensure_discovered()
    if feed_id not in _FEEDS:
        raise KeyError(feed_id)

    feed = _FEEDS[feed_id]
    store = _get_state_store(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()

    state: Dict[str, Any] = {
        "last_imported_at": now_iso,
        "last_status": "ok",
        "last_error": None,
        "last_result": None,
        "last_entry_count": None,
    }

    try:
        result = feed.importer_callable()
        if not isinstance(result, dict):
            result = {"raw": result}
        state["last_result"] = result
        # Try to derive an entry count from common keys
        derived = (
            result.get("source_count")
            or result.get("rules")
            or (
                (result.get("techniques") or 0)
                + (result.get("subtechniques") or 0)
            )
            or result.get("imported")
            or result.get("scores_imported")
        )
        if not derived and feed.count_callable is not None:
            try:
                derived = feed.count_callable()
            except Exception:  # noqa: BLE001
                derived = None
        state["last_entry_count"] = int(derived) if derived else 0
    except Exception as exc:  # noqa: BLE001
        logger.exception("feed_registry: refresh failed for %s", feed_id)
        state["last_status"] = "error"
        state["last_error"] = f"{type(exc).__name__}: {exc}"

    with _state_lock:
        try:
            store[feed_id] = state
        except Exception as exc:  # noqa: BLE001
            logger.warning("feed_registry: failed to persist state for %s: %s", feed_id, exc)

    return {
        "feed_id": feed_id,
        "status": state["last_status"],
        "imported_at": state["last_imported_at"],
        "entry_count": state["last_entry_count"],
        "result": state["last_result"],
        "error": state["last_error"],
    }


# ---------------------------------------------------------------------------
# Test helpers (NOT part of the public API but useful for unit tests)
# ---------------------------------------------------------------------------

def _reset_for_tests() -> None:
    """Drop the in-process registry + state cache. Tests only."""
    global _discovery_done, _state_store
    with _discovery_lock:
        _FEEDS.clear()
        _discovery_done = False
    _state_store = None


def _force_register(feed: FeedDefinition) -> None:
    """Forcibly add a feed (overwriting any existing entry). Tests only."""
    _ensure_discovered()
    _FEEDS[feed.id] = feed
