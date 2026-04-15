#!/usr/bin/env python3
"""ALDECI Demo Data Seeder — seeds investor-quality demo data into all engines.

Usage:
    python scripts/seed_demo_data.py [--org-id aldeci-demo] [--reset]
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Allow running from repo root OR from scripts/
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suite-core"))

ORG_ID = "aldeci-demo"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(days_ago: int = 0, hours_ago: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp offset from now."""
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)
    return dt.isoformat()


def _date(days_ago: int = 0, days_ahead: int = 0) -> str:
    """Return a YYYY-MM-DD date string relative to today."""
    from datetime import date, timedelta as td
    d = date.today() + td(days=days_ahead) - td(days=days_ago)
    return d.isoformat()


# ---------------------------------------------------------------------------
# 1. PostureScoreEngine
# ---------------------------------------------------------------------------

def seed_posture(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 12 monthly posture score history snapshots + 8 component scores."""
    from core.posture_score_engine import PostureScoreEngine

    engine = PostureScoreEngine()

    if reset:
        import sqlite3
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute("DELETE FROM posture_scores WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM score_history WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM score_components WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM benchmarks WHERE org_id=?", (org_id,))

    # End-state component scores (healthy, trending up)
    component_data = {
        "vulnerability_mgmt_score": 78,
        "identity_security_score":  82,
        "endpoint_security_score":  76,
        "network_security_score":   80,
        "cloud_security_score":     71,
        "compliance_score":         74,
        "incident_response_score":  69,
        "training_score":           85,
    }
    for comp, score in component_data.items():
        engine.update_component(org_id, comp, score, source="demo_seeder")

    # 12 monthly history snapshots trending from 58 -> 74
    monthly_scores = [58, 59, 61, 62, 63, 65, 66, 68, 69, 71, 72, 74]
    grades         = ["F", "F", "D", "D", "D", "D", "D", "D", "D", "C", "C", "C"]
    trends         = (["stable"] + ["improving"] * 11)

    import sqlite3, uuid, json
    with sqlite3.connect(engine.db_path) as conn:
        for i, (score, grade, trend) in enumerate(zip(monthly_scores, grades, trends)):
            days_ago = (12 - i) * 30
            recorded_at = _ts(days_ago=days_ago)
            ratio = score / 74.0
            comp_snapshot = {k: int(v * ratio) for k, v in component_data.items()}
            conn.execute(
                """INSERT OR IGNORE INTO score_history
                   (id, org_id, overall_score, grade, components, recorded_at)
                   VALUES (?,?,?,?,?,?)""",
                (str(uuid.uuid4()), org_id, score, grade,
                 json.dumps(comp_snapshot), recorded_at),
            )

    # Save current snapshot
    score_data = engine.compute_posture_score(org_id)
    engine.save_score(org_id, score_data)

    # Industry benchmark
    engine.add_benchmark(org_id, {
        "industry": "Technology",
        "company_size": "mid_market",
        "avg_score": 68.0,
        "percentile_rank": 72,
        "source": "Gartner Security Benchmark 2025",
        "as_of_date": "2025-01-01",
    })

    stats = engine.get_posture_stats(org_id)
    return {"engine": "PostureScoreEngine",
            "current_score": stats["current_score"],
            "grade": stats["grade"],
            "history_snapshots": 12}


# ---------------------------------------------------------------------------
# 2. ThreatFeedAggregator
# ---------------------------------------------------------------------------

def seed_threat_feeds(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 8 feed sources + 20 realistic threat intel items."""
    from core.threat_feed_aggregator import ThreatFeedAggregator

    engine = ThreatFeedAggregator()

    if reset:
        import sqlite3
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute("DELETE FROM feed_sources WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM feed_items WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM feed_subscriptions WHERE org_id=?", (org_id,))

    sources_def = [
        {"name": "NVD CVE Feed",       "feed_type": "cve",            "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",                           "format": "json", "update_frequency_minutes": 360,  "reliability_score": 99},
        {"name": "abuse.ch URLhaus",   "feed_type": "domain_blocklist","url": "https://urlhaus.abuse.ch/downloads/json/",                                                     "format": "json", "update_frequency_minutes": 60,   "reliability_score": 95},
        {"name": "AlienVault OTX",     "feed_type": "apt_campaign",   "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",                                           "format": "json", "update_frequency_minutes": 120,  "reliability_score": 92},
        {"name": "URLhaus Malware",    "feed_type": "malware",        "url": "https://urlhaus.abuse.ch/downloads/payloads/",                                                   "format": "csv",  "update_frequency_minutes": 60,   "reliability_score": 93},
        {"name": "Feodo C2 Tracker",  "feed_type": "ip_blocklist",   "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",                                       "format": "json", "update_frequency_minutes": 30,   "reliability_score": 96},
        {"name": "CISA KEV Catalog",  "feed_type": "vulnerability",  "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",           "format": "json", "update_frequency_minutes": 1440, "reliability_score": 100},
        {"name": "Shodan InternetDB", "feed_type": "osint",           "url": "https://internetdb.shodan.io/",                                                                  "format": "json", "update_frequency_minutes": 240,  "reliability_score": 88},
        {"name": "MalwareBazaar",     "feed_type": "malware",        "url": "https://bazaar.abuse.ch/export/json/recent/",                                                    "format": "json", "update_frequency_minutes": 60,   "reliability_score": 94},
    ]

    source_ids = []
    for s in sources_def:
        result = engine.add_feed_source(org_id, s)
        source_ids.append(result["source_id"])

    feed_items = [
        # CVEs
        {"si": 0, "data": {"feed_type": "cve",  "severity": "critical", "title": "CVE-2025-0001 — RCE in OpenSSL 3.x",                    "description": "Heap buffer overflow allowing unauthenticated RCE via crafted TLS handshake.",                                                       "iocs": ["CVE-2025-0001"],                                                  "published_at": _ts(days_ago=2)}},
        {"si": 0, "data": {"feed_type": "cve",  "severity": "high",     "title": "CVE-2025-0234 — Privilege Escalation in Linux Kernel 6.x","description": "Local privilege escalation via ioctl race condition in io_uring.",                                                                 "iocs": ["CVE-2025-0234"],                                                  "published_at": _ts(days_ago=5)}},
        {"si": 0, "data": {"feed_type": "cve",  "severity": "high",     "title": "CVE-2025-1102 — SQL Injection in Django ORM 4.2",         "description": "Blind SQLi via annotate() with user-controlled QuerySet.",                                                                          "iocs": ["CVE-2025-1102"],                                                  "published_at": _ts(days_ago=8)}},
        # Malware
        {"si": 3, "data": {"feed_type": "malware","severity": "critical","title": "BlackCat Ransomware Payload — Updated EDR bypass variant", "description": "ALPHV/BlackCat updated with improved EDR bypass and BYOVD technique.",                                                             "iocs": ["a3f9b2c1d4e5f6a7b8c9d0e1", "192.168.99.44"],                      "published_at": _ts(days_ago=1)}},
        {"si": 7, "data": {"feed_type": "malware","severity": "high",    "title": "AgentTesla Stealer — New C2 Infrastructure",              "description": "AgentTesla variant targeting finance sector with updated SMTP exfil channel.",                                                      "iocs": ["malware-c2.badactor.ru", "185.220.101.55"],                       "published_at": _ts(days_ago=3)}},
        {"si": 7, "data": {"feed_type": "malware","severity": "high",    "title": "Emotet Epoch 5 — Resuming Activity",                      "description": "Emotet botnet resumed spam campaigns with updated Word macro dropper.",                                                              "iocs": ["emotet-epoch5.example.com", "103.45.67.89"],                      "published_at": _ts(days_ago=6)}},
        # IP blocklist
        {"si": 4, "data": {"feed_type": "ip_blocklist","severity": "high","title": "Feodo C2 Server — Emotet Infrastructure",               "description": "Active Emotet C2 nodes hosting botnet command infrastructure.",                                                                     "iocs": ["185.234.219.108", "51.178.61.60", "103.75.201.2"],               "published_at": _ts(days_ago=1)}},
        {"si": 4, "data": {"feed_type": "ip_blocklist","severity": "high","title": "IcedID Banking Trojan C2 Cluster",                       "description": "IcedID C2 servers used in recent banking sector campaigns.",                                                                         "iocs": ["91.243.44.148", "194.61.55.219"],                                 "published_at": _ts(days_ago=2)}},
        # Domain blocklist
        {"si": 1, "data": {"feed_type": "domain_blocklist","severity": "high",  "title": "Phishing domains targeting ALDECI customers",     "description": "Lookalike domains registered to harvest credentials from enterprise users.",                                                         "iocs": ["aldeci-login.phish.xyz", "secure-aldeci.tk"],                    "published_at": _ts(days_ago=4)}},
        {"si": 1, "data": {"feed_type": "domain_blocklist","severity": "medium","title": "URLhaus: Active malware distribution URLs",         "description": "150+ URLs actively distributing Raccoon Stealer payloads.",                                                                          "iocs": ["hxxp://evil-cdn.biz/payload.exe"],                                "published_at": _ts(days_ago=7)}},
        # APT campaigns
        {"si": 2, "data": {"feed_type": "apt_campaign","severity": "critical","title": "APT41 — Supply Chain Campaign Targeting SaaS Vendors","description": "Chinese nation-state actor targeting software supply chains via CI/CD pipeline compromise. DLL sideloading TTPs.",              "iocs": ["apt41-c2.hk-hosting.com", "update-srv.software-cdn.net"],        "published_at": _ts(days_ago=3)}},
        {"si": 2, "data": {"feed_type": "apt_campaign","severity": "critical","title": "Lazarus Group — Crypto Theft Operation 2025",         "description": "North Korean APT targeting crypto exchanges via spear-phishing with malicious PDF attachments.",                                  "iocs": ["lazarus-job-offer.pdf", "nk-c2.hosting.io", "CVE-2024-38021"],   "published_at": _ts(days_ago=5)}},
        {"si": 2, "data": {"feed_type": "apt_campaign","severity": "high",    "title": "FIN7 — New Carbanak Variant Targeting Retail",        "description": "FIN7 updated Carbanak with living-off-the-land techniques to evade EDR. Targeting POS systems.",                                  "iocs": ["carbanak-c2.cdn-update.net", "205.185.119.17"],                   "published_at": _ts(days_ago=10)}},
        # Vulnerabilities (CISA KEV)
        {"si": 5, "data": {"feed_type": "vulnerability","severity": "critical","title": "CISA KEV: CVE-2024-49138 — Windows CLFS Driver EoP","description": "Windows CLFS driver privilege escalation, exploited by ransomware groups. Patch immediately.",                                    "iocs": ["CVE-2024-49138"],                                                 "published_at": _ts(days_ago=14)}},
        {"si": 5, "data": {"feed_type": "vulnerability","severity": "critical","title": "CISA KEV: CVE-2025-0282 — Ivanti Connect Secure RCE","description": "Pre-auth RCE in Ivanti Connect Secure. Active exploitation by UNC5337.",                                                          "iocs": ["CVE-2025-0282"],                                                 "published_at": _ts(days_ago=10)}},
        {"si": 5, "data": {"feed_type": "vulnerability","severity": "high",   "title": "CISA KEV: CVE-2024-55956 — Cleo File Transfer RCE",  "description": "Unauthenticated deserialization RCE in Cleo Harmony/VLTrader. CLOP ransomware exploiting.",                                     "iocs": ["CVE-2024-55956"],                                                 "published_at": _ts(days_ago=8)}},
        # OSINT (Shodan)
        {"si": 6, "data": {"feed_type": "osint","severity": "medium","title": "Shodan: 47 Exposed Redis Instances in Org IP Space",           "description": "Unauthenticated Redis instances on internet-facing infra. Risk of data theft and cryptomining.",                                  "iocs": ["203.0.113.15", "203.0.113.28", "203.0.113.41"],                  "published_at": _ts(days_ago=1)}},
        {"si": 6, "data": {"feed_type": "osint","severity": "medium","title": "Shodan: Outdated Elasticsearch 7.x Nodes Exposed",             "description": "8 Elasticsearch nodes running EOL 7.x with no authentication.",                                                                    "iocs": ["198.51.100.7", "198.51.100.23"],                                 "published_at": _ts(days_ago=3)}},
        # Additional
        {"si": 3, "data": {"feed_type": "malware","severity": "medium","title": "XWorm RAT — Updated Persistence Mechanism",                  "description": "XWorm RAT updated with scheduled task persistence and UAC bypass via DLL hijacking.",                                               "iocs": ["xworm-c2.onion.ws"],                                              "published_at": _ts(days_ago=12)}},
        {"si": 1, "data": {"feed_type": "domain_blocklist","severity": "low","title": "Newly registered suspicious domains — Batch 2025-04-15","description": "43 domains registered in last 24h matching typosquat patterns for financial institutions.",                                     "iocs": ["paypa1-secure.com", "microsofft-login.net"],                     "published_at": _ts(days_ago=1)}},
    ]

    items_created = 0
    for item in feed_items:
        engine.ingest_feed_item(org_id, source_ids[item["si"]], item["data"])
        items_created += 1

    stats = engine.get_feed_stats(org_id)
    return {"engine": "ThreatFeedAggregator",
            "sources": stats["total_sources"],
            "items": items_created}


# ---------------------------------------------------------------------------
# 3. DigitalForensicsEngine
# ---------------------------------------------------------------------------

def seed_forensics(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 5 forensic cases with evidence and chain of custody."""
    from core.digital_forensics_engine import DigitalForensicsEngine

    engine = DigitalForensicsEngine()

    if reset:
        import sqlite3
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute("DELETE FROM forensic_cases WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM evidence_items WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM analysis_results WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM chain_of_custody WHERE org_id=?", (org_id,))

    cases_def = [
        {"title": "BlackCat Ransomware — Finance Cluster Outbreak",   "case_type": "ransom",      "status": "active",  "priority": "critical", "assigned_analyst": "alice@aldeci.io",  "related_incident_id": "INC-2025-0041"},
        {"title": "Insider Exfiltration — Departing Sales Engineer",  "case_type": "insider",     "status": "active",  "priority": "high",     "assigned_analyst": "bob@aldeci.io",    "related_incident_id": "INC-2025-0038"},
        {"title": "APT41 Supply Chain Compromise Investigation",      "case_type": "malware",     "status": "open",    "priority": "critical", "assigned_analyst": "carol@aldeci.io",  "related_incident_id": "INC-2025-0035"},
        {"title": "PCI Data Breach — E-commerce Web Application",    "case_type": "data_breach", "status": "closed",  "priority": "critical", "assigned_analyst": "david@aldeci.io",  "related_incident_id": "INC-2025-0029"},
        {"title": "AgentTesla Dropper — HR Workstation Infection",   "case_type": "malware",     "status": "active",  "priority": "medium",   "assigned_analyst": "eve@aldeci.io",    "related_incident_id": "INC-2025-0044"},
    ]

    # Evidence per case: [list of evidence dicts]
    evidence_per_case = [
        [   # Case 0: BlackCat Ransomware
            {"evidence_type": "memory_dump", "filename": "finance-srv-01_memdump.dmp",   "size_bytes": 34_359_738_368, "hash_md5": "d41d8cd98f00b204e9800998ecf8427e", "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb924", "collected_by": "alice@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0041/"},
            {"evidence_type": "disk_image",  "filename": "finance-srv-01_disk.img",       "size_bytes": 274_877_906_944,"hash_md5": "c4ca4238a0b923820dcc509a6f75849b", "hash_sha256": "6b86b273ff34fce19d6b804eff5a3f57", "collected_by": "alice@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0041/"},
            {"evidence_type": "log_file",    "filename": "finance-srv-01_eventlog.evtx",  "size_bytes": 67_108_864,     "hash_md5": "eccbc87e4b5ce2fe28308fd9f2a7baf3", "hash_sha256": "d4735e3a265e16eee03f59718b9b5d03", "collected_by": "alice@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0041/"},
            {"evidence_type": "pcap",        "filename": "finance-cluster_network.pcap",  "size_bytes": 2_147_483_648,  "hash_md5": "a87ff679a2f3e71d9181a67b7542122c", "hash_sha256": "4b227777d4dd1fc61c6f884f48641d02", "collected_by": "alice@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0041/"},
        ],
        [   # Case 1: Insider
            {"evidence_type": "log_file",    "filename": "dlp_exfil_events_2025-04-10.csv","size_bytes": 1_048_576,      "hash_md5": "1679091c5a880faf6fb5e6087eb1b2dc", "hash_sha256": "ef2d127de37b942baad06145e54b0c6", "collected_by": "bob@aldeci.io",   "storage_location": "s3://aldeci-forensics/INC-2025-0038/"},
            {"evidence_type": "log_file",    "filename": "active_directory_audit.log",      "size_bytes": 524_288,         "hash_md5": "8f14e45fceea167a5a36dedd4bea2543", "hash_sha256": "e7f6c011776e8db7cd330b54174fd76f", "collected_by": "bob@aldeci.io",   "storage_location": "s3://aldeci-forensics/INC-2025-0038/"},
            {"evidence_type": "mobile_image","filename": "corporate_iphone_image.tar.gz",   "size_bytes": 16_106_127_360,  "hash_md5": "c9f0f895fb98ab9159f51fd0297e236d", "hash_sha256": "7902699be42c8a8e46fbebb4501726517", "collected_by": "bob@aldeci.io",   "storage_location": "s3://aldeci-forensics/INC-2025-0038/"},
        ],
        [   # Case 2: APT41
            {"evidence_type": "malware_sample","filename": "apt41_dropper.bin",            "size_bytes": 245_760,          "hash_md5": "45c48cce2e2d7fbdea1afc51c7c6ad26", "hash_sha256": "17ba0791499db908433b80f37c5fbc8", "collected_by": "carol@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0035/"},
            {"evidence_type": "pcap",          "filename": "cicd_pipeline_traffic.pcap",   "size_bytes": 536_870_912,      "hash_md5": "6512bd43d9caa6e02c990b0a82652dca", "hash_sha256": "7902699be42c8a8e46fbebb4501726518", "collected_by": "carol@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0035/"},
            {"evidence_type": "log_file",      "filename": "github_actions_audit.json",    "size_bytes": 2_097_152,         "hash_md5": "c20ad4d76fe97759aa27a0c99bff6710", "hash_sha256": "4e07408562bedb8b60ce05c1decb3f4c", "collected_by": "carol@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0035/"},
            {"evidence_type": "registry_hive", "filename": "build_server_ntuser.dat",      "size_bytes": 8_388_608,         "hash_md5": "c51ce410c124a10e0db5e4b97fc2af39", "hash_sha256": "2c624232cdd221771294dfbb310acbc8", "collected_by": "carol@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0035/"},
        ],
        [   # Case 3: PCI Data Breach (closed)
            {"evidence_type": "disk_image",  "filename": "ecomm-webserver_disk.img",       "size_bytes": 137_438_953_472,  "hash_md5": "aab3238922bcc25a6f606eb525ffdc56", "hash_sha256": "19581e27de7ced00ff1ce50b2047e7a5", "collected_by": "david@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0029/"},
            {"evidence_type": "log_file",    "filename": "nginx_access_breach_period.gz",  "size_bytes": 4_294_967_296,    "hash_md5": "9bf31c7ff062936a96d3c8bd1f8f2ff3", "hash_sha256": "4a44dc15364204a80fe80e9039455cc1", "collected_by": "david@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0029/"},
            {"evidence_type": "pcap",        "filename": "ecomm_exfil_traffic.pcap",       "size_bytes": 1_073_741_824,    "hash_md5": "c74d97b01eae257e44aa9d5bade97baf", "hash_sha256": "35135aaa6cc23891b40cb3f378c53a1", "collected_by": "david@aldeci.io", "storage_location": "s3://aldeci-forensics/INC-2025-0029/"},
        ],
        [   # Case 4: AgentTesla
            {"evidence_type": "malware_sample","filename": "hr_attachment_agenttesla.docm","size_bytes": 102_400,           "hash_md5": "70efdf2ec9b086079795c442636b55fb", "hash_sha256": "68b329da9893e34099c7d8ad5cb9c940", "collected_by": "eve@aldeci.io",   "storage_location": "s3://aldeci-forensics/INC-2025-0044/"},
            {"evidence_type": "memory_dump",   "filename": "hr-workstation-14_memdump.dmp","size_bytes": 17_179_869_184,   "hash_md5": "6f4922f45568161a8cdf4ad2299f6d23", "hash_sha256": "11abe56a786fe1fc276b8e52bc74a4dc", "collected_by": "eve@aldeci.io",   "storage_location": "s3://aldeci-forensics/INC-2025-0044/"},
            {"evidence_type": "log_file",      "filename": "hr-workstation-14_events.evtx","size_bytes": 33_554_432,       "hash_md5": "1f0e3dad99908345f7439f8ffabdffc4", "hash_sha256": "6b86b273ff34fce19d6b804eff5a3f58", "collected_by": "eve@aldeci.io",   "storage_location": "s3://aldeci-forensics/INC-2025-0044/"},
        ],
    ]

    analysis_per_case = [
        [{"analysis_type": "memory",  "findings": ["BlackCat injected into svchost.exe", "Mimikatz credential dump artifacts", "BYOVD driver: Netfilter64.sys"],                                            "iocs_extracted": ["a3f9b2c1d4e5f6a7", "192.168.99.44", "blackcat-c2.onion"], "tool_used": "Volatility 3 + YARA",        "analyst": "alice@aldeci.io"}],
        [{"analysis_type": "timeline","findings": ["7.2 GB uploaded to personal Dropbox over 3 weeks", "Access to 4,200 customer PII records outside business hours", "USB device connected 12 times"],  "iocs_extracted": ["dropbox.com/uploads", "usb_serial_7F3A21B9"],            "tool_used": "ALDECI DLP + Elastic SIEM", "analyst": "bob@aldeci.io"}],
        [{"analysis_type": "static",  "findings": ["Signed dropper with stolen Nvidia cert", "DLL sideloading via update.exe", "Backdoor TCP/443 with custom JA3"],                                        "iocs_extracted": ["apt41-c2.hk-hosting.com"],                               "tool_used": "Ghidra + IDA Pro",           "analyst": "carol@aldeci.io"},
         {"analysis_type": "network", "findings": ["DNS beaconing every 60s to *.software-cdn.net", "Data exfil via HTTPS to 203.76.251.21", "Lateral movement to 3 build servers"],                     "iocs_extracted": ["software-cdn.net", "203.76.251.21"],                     "tool_used": "Zeek + Suricata",           "analyst": "carol@aldeci.io"}],
        [{"analysis_type": "network", "findings": ["SQL injection in /checkout", "8,432 payment cards exfiltrated to 185.220.70.91", "Dwell time: 11 days"],                                               "iocs_extracted": ["185.220.70.91", "CVE-2024-1234"],                        "tool_used": "Burp Suite + Wireshark",    "analyst": "david@aldeci.io"}],
        [{"analysis_type": "static",  "findings": ["AgentTesla with SMTP exfil to attacker Gmail", "Keylogger at HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Screenshot every 30s"],       "iocs_extracted": ["agentexfil@gmail.com"],                                  "tool_used": "Any.run + VirusTotal",      "analyst": "eve@aldeci.io"}],
    ]

    cases_created = evidence_created = analyses_created = 0

    for i, case_def in enumerate(cases_def):
        case = engine.create_case(org_id, case_def)
        case_id = case["case_id"]
        cases_created += 1

        if case_def["status"] == "closed":
            engine.close_case(org_id, case_id)

        evidence_ids = []
        for ev in evidence_per_case[i]:
            e = engine.add_evidence(org_id, case_id, ev)
            evidence_ids.append(e["evidence_id"])
            evidence_created += 1
            engine.log_chain_of_custody(org_id=org_id, evidence_id=e["evidence_id"],
                                        action="transferred", actor="forensics-lead@aldeci.io",
                                        notes="Transferred to senior analyst for deep-dive")

        for analysis in analysis_per_case[i]:
            analysis["evidence_id"] = evidence_ids[0] if evidence_ids else ""
            engine.add_analysis_result(org_id, case_id, analysis)
            analyses_created += 1

    stats = engine.get_forensics_stats(org_id)
    return {"engine": "DigitalForensicsEngine", "cases": cases_created,
            "evidence_items": evidence_created, "analyses": analyses_created,
            "open_cases": stats["open_cases"]}


# ---------------------------------------------------------------------------
# 4. SecurityRoadmapEngine
# ---------------------------------------------------------------------------

def seed_roadmap(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 8 initiatives with 3-5 milestones each, plus 4 capability gaps."""
    from core.security_roadmap_engine import SecurityRoadmapEngine

    engine = SecurityRoadmapEngine()

    if reset:
        import sqlite3
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute("DELETE FROM roadmap_initiatives WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM initiative_milestones WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM roadmap_gaps WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM roadmap_metrics WHERE org_id=?", (org_id,))

    initiatives_def = [
        {"title": "Zero Trust Network Architecture",       "category": "technology", "priority": "critical","status": "in_progress","owner": "CISO",           "budget_usd": 450_000,"start_date": _date(days_ago=120),"target_date": _date(days_ahead=180),"risk_reduction_score": 35.0,
         "milestones": [
             {"title": "Identity perimeter assessment",       "status": "completed",  "due_date": _date(days_ago=90)},
             {"title": "Microsegmentation design approved",   "status": "completed",  "due_date": _date(days_ago=60)},
             {"title": "Pilot deployment (prod zone A)",      "status": "in_progress","due_date": _date(days_ahead=30)},
             {"title": "Full rollout + SIEM integration",     "status": "pending",    "due_date": _date(days_ahead=120)},
             {"title": "Red team validation",                 "status": "pending",    "due_date": _date(days_ahead=160)},
         ]},
        {"title": "SOC2 Type II Certification",            "category": "compliance", "priority": "high",    "status": "in_progress","owner": "GRC Team",       "budget_usd": 180_000,"start_date": _date(days_ago=90), "target_date": _date(days_ahead=90), "risk_reduction_score": 25.0,
         "milestones": [
             {"title": "Gap assessment completed",            "status": "completed",  "due_date": _date(days_ago=60)},
             {"title": "Policy documentation finalized",     "status": "completed",  "due_date": _date(days_ago=30)},
             {"title": "Readiness audit (internal)",          "status": "in_progress","due_date": _date(days_ahead=15)},
             {"title": "External auditor engagement",         "status": "pending",    "due_date": _date(days_ahead=60)},
         ]},
        {"title": "Cloud Security Posture Management",     "category": "technology", "priority": "high",    "status": "in_progress","owner": "Cloud Sec",      "budget_usd": 95_000, "start_date": _date(days_ago=60), "target_date": _date(days_ahead=60), "risk_reduction_score": 20.0,
         "milestones": [
             {"title": "AWS/Azure/GCP inventory completed",  "status": "completed",  "due_date": _date(days_ago=30)},
             {"title": "CSPM tooling deployed",              "status": "in_progress","due_date": _date(days_ahead=10)},
             {"title": "Baseline policy set enforced",       "status": "pending",    "due_date": _date(days_ahead=45)},
         ]},
        {"title": "Security Awareness Training v2",        "category": "people",     "priority": "medium",  "status": "in_progress","owner": "HR + Security",  "budget_usd": 40_000, "start_date": _date(days_ago=30), "target_date": _date(days_ahead=60), "risk_reduction_score": 15.0,
         "milestones": [
             {"title": "LMS platform selected",              "status": "completed",  "due_date": _date(days_ago=20)},
             {"title": "Phishing simulation baseline",       "status": "completed",  "due_date": _date(days_ago=10)},
             {"title": "Role-based training modules live",   "status": "pending",    "due_date": _date(days_ahead=30)},
             {"title": "First quarterly phishing exercise",  "status": "pending",    "due_date": _date(days_ahead=55)},
         ]},
        {"title": "Vulnerability Management Modernization","category": "process",    "priority": "high",    "status": "in_progress","owner": "Vuln Mgmt Lead", "budget_usd": 75_000, "start_date": _date(days_ago=45), "target_date": _date(days_ahead=45), "risk_reduction_score": 22.0,
         "milestones": [
             {"title": "Scanning coverage audit",            "status": "completed",  "due_date": _date(days_ago=30)},
             {"title": "CVSS x EPSS x KEV prioritization",  "status": "in_progress","due_date": _date(days_ahead=5)},
             {"title": "SLA policy published",               "status": "pending",    "due_date": _date(days_ahead=20)},
             {"title": "Patch cadence < 30 days",            "status": "pending",    "due_date": _date(days_ahead=40)},
         ]},
        {"title": "GDPR & Data Privacy Compliance Uplift", "category": "compliance", "priority": "high",    "status": "planned",    "owner": "DPO",            "budget_usd": 120_000,"start_date": _date(days_ahead=30),"target_date": _date(days_ahead=180),"risk_reduction_score": 18.0,
         "milestones": [
             {"title": "Data inventory & mapping (ROPA)",    "status": "pending",    "due_date": _date(days_ahead=60)},
             {"title": "DSAR workflow automation",           "status": "pending",    "due_date": _date(days_ahead=90)},
             {"title": "DPO external certification",         "status": "pending",    "due_date": _date(days_ahead=150)},
         ]},
        {"title": "Insider Threat Detection Program",      "category": "technology", "priority": "medium",  "status": "planned",    "owner": "SOC Manager",    "budget_usd": 65_000, "start_date": _date(days_ahead=15),"target_date": _date(days_ahead=120),"risk_reduction_score": 12.0,
         "milestones": [
             {"title": "UEBA baseline established",          "status": "pending",    "due_date": _date(days_ahead=30)},
             {"title": "Watchlist policies configured",      "status": "pending",    "due_date": _date(days_ahead=60)},
             {"title": "Playbook integration (SOAR)",        "status": "pending",    "due_date": _date(days_ahead=100)},
         ]},
        {"title": "IR Tabletop & Retainer",                "category": "process",    "priority": "medium",  "status": "completed",  "owner": "IR Lead",        "budget_usd": 30_000, "start_date": _date(days_ago=180),"target_date": _date(days_ago=30),  "completion_date": _date(days_ago=25),"risk_reduction_score": 10.0,
         "milestones": [
             {"title": "IR playbooks written",              "status": "completed",  "due_date": _date(days_ago=150)},
             {"title": "Tabletop exercise — ransomware",    "status": "completed",  "due_date": _date(days_ago=90)},
             {"title": "Retainer signed with IR firm",      "status": "completed",  "due_date": _date(days_ago=30)},
         ]},
    ]

    gaps_def = [
        {"title": "No privileged access workstation (PAW) policy",        "gap_type": "capability", "severity": "critical","description": "Admin accounts used on regular workstations, exposing credentials to keyloggers and RATs."},
        {"title": "Lack of formal TPRM process",                          "gap_type": "compliance", "severity": "high",    "description": "40% of critical vendors have not completed security questionnaires in the past 12 months."},
        {"title": "No FIDO2 hardware key for privileged users",           "gap_type": "technology", "severity": "high",    "description": "MFA relies on TOTP only; FIDO2/WebAuthn not deployed for admin accounts."},
        {"title": "Security champion program not established",             "gap_type": "people",     "severity": "medium",  "description": "No embedded security champions in engineering squads. Secure-by-default culture weak."},
    ]

    initiatives_created = milestones_created = 0

    for init_def in initiatives_def:
        milestones = init_def.pop("milestones", [])
        initiative = engine.create_initiative(org_id, init_def)
        iid = initiative["initiative_id"]
        initiatives_created += 1

        for ms in milestones:
            m = engine.add_milestone(org_id, iid, ms)
            if ms.get("status") == "completed":
                engine.complete_milestone(org_id, m["milestone_id"])
            milestones_created += 1

        engine.add_metric(org_id, iid, {
            "metric_name":    "Risk Reduction Score",
            "target_value":   init_def.get("risk_reduction_score", 10.0),
            "current_value":  init_def.get("risk_reduction_score", 10.0) * 0.6,
            "unit":           "points",
        })

    for gap_def in gaps_def:
        engine.add_gap(org_id, gap_def)

    stats = engine.get_roadmap_stats(org_id)
    return {"engine": "SecurityRoadmapEngine", "initiatives": initiatives_created,
            "milestones": milestones_created, "gaps": len(gaps_def),
            "total_budget": stats["total_budget"]}


# ---------------------------------------------------------------------------
# 5. DataGovernanceEngine
# ---------------------------------------------------------------------------

def seed_data_governance(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 12 data assets, 6 policies, 3 open violations."""
    from core.data_governance_engine import DataGovernanceEngine

    engine = DataGovernanceEngine()

    if reset:
        import sqlite3
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute("DELETE FROM data_assets WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM governance_policies WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM policy_violations WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM data_flows WHERE org_id=?", (org_id,))

    assets_def = [
        {"name": "Customer PII Database (prod-pg-01)",     "asset_type": "database",      "classification": "restricted",   "owner": "data-eng@aldeci.io",  "data_categories": ["PII"],        "retention_days": 730,  "location": "AWS RDS us-east-1",        "encrypted": True},
        {"name": "Payment Card DB (pci-pg-01)",            "asset_type": "database",      "classification": "secret",       "owner": "payments@aldeci.io",  "data_categories": ["PCI"],        "retention_days": 365,  "location": "AWS RDS us-east-1 (VPC)",  "encrypted": True},
        {"name": "Employee HR Records (hr-pg-01)",         "asset_type": "database",      "classification": "confidential", "owner": "hr@aldeci.io",         "data_categories": ["PII"],        "retention_days": 2555, "location": "Azure SQL East US",        "encrypted": True},
        {"name": "Patient Health Records (hipaa-rds-01)",  "asset_type": "database",      "classification": "secret",       "owner": "health@aldeci.io",     "data_categories": ["PHI", "PII"],"retention_days": 2555, "location": "AWS RDS us-east-1 (Priv)", "encrypted": True},
        {"name": "S3 Analytics Data Lake (raw zone)",      "asset_type": "cloud_storage", "classification": "internal",     "owner": "analytics@aldeci.io",  "data_categories": ["PII"],        "retention_days": 365,  "location": "AWS S3 us-east-1",         "encrypted": True},
        {"name": "S3 Backup Bucket (prod-backups)",        "asset_type": "cloud_storage", "classification": "confidential", "owner": "devops@aldeci.io",      "data_categories": ["PII", "PCI"],"retention_days": 730,  "location": "AWS S3 us-west-2",         "encrypted": False},
        {"name": "Marketing Analytics Warehouse (BQ)",     "asset_type": "database",      "classification": "internal",     "owner": "marketing@aldeci.io",  "data_categories": [],             "retention_days": 180,  "location": "GCP BigQuery us-central1", "encrypted": True},
        {"name": "Audit Logs — Immutable Store (S3)",      "asset_type": "cloud_storage", "classification": "confidential", "owner": "security@aldeci.io",   "data_categories": [],             "retention_days": 2555, "location": "AWS S3 (WORM)",            "encrypted": True},
        {"name": "Public CDN Assets (cloudfront-01)",      "asset_type": "cloud_storage", "classification": "public",       "owner": "engineering@aldeci.io","data_categories": [],             "retention_days": 90,   "location": "AWS CloudFront",           "encrypted": False},
        {"name": "Payments REST API (api-payments-v2)",    "asset_type": "api_endpoint",  "classification": "secret",       "owner": "payments@aldeci.io",   "data_categories": ["PCI"],        "retention_days": 0,    "location": "AWS API Gateway + Lambda", "encrypted": True},
        {"name": "Customer Identity API (auth-api-v3)",    "asset_type": "api_endpoint",  "classification": "restricted",   "owner": "identity@aldeci.io",   "data_categories": ["PII"],        "retention_days": 0,    "location": "AWS API Gateway + Lambda", "encrypted": True},
        {"name": "Real-Time Event Stream (Kafka prod)",    "asset_type": "data_stream",   "classification": "confidential", "owner": "platform@aldeci.io",   "data_categories": ["PII"],        "retention_days": 7,    "location": "AWS MSK us-east-1",        "encrypted": True},
    ]

    asset_ids = []
    for a in assets_def:
        result = engine.register_asset(org_id, a)
        asset_ids.append(result["asset_id"])

    policies_def = [
        {"name": "PCI DSS Data Retention Policy",              "policy_type": "retention",  "applies_to_classification": "secret",       "requirement": "Cardholder data must not be retained beyond authorization. Purge within 90 days.",         "enforcement": "automated", "status": "active"},
        {"name": "GDPR Data Encryption at Rest",               "policy_type": "encryption", "applies_to_classification": "restricted",   "requirement": "All restricted+ data encrypted at rest using AES-256.",                                    "enforcement": "automated", "status": "active"},
        {"name": "Cross-Border Transfer Approval Policy",      "policy_type": "transfer",   "applies_to_classification": "confidential", "requirement": "Any transfer outside EU/US requires DPO sign-off and SCC execution.",                      "enforcement": "manual",    "status": "active"},
        {"name": "API Access Control — Least Privilege",       "policy_type": "access",     "applies_to_classification": "secret",       "requirement": "All secret APIs must enforce OAuth 2.0 scopes and per-request audit logging.",              "enforcement": "automated", "status": "active"},
        {"name": "Data Deletion — Right to Erasure (Art. 17)","policy_type": "deletion",   "applies_to_classification": "restricted",   "requirement": "PII deletion requests fulfilled within 30 days. Automated deletion pipeline required.",      "enforcement": "advisory",  "status": "active"},
        {"name": "Backup Encryption Policy",                   "policy_type": "encryption", "applies_to_classification": "confidential", "requirement": "All backup data at confidential+ must be encrypted in transit and at rest.",                "enforcement": "manual",    "status": "active"},
    ]

    policy_ids = []
    for p in policies_def:
        result = engine.create_policy(org_id, p)
        policy_ids.append(result["policy_id"])

    violations_def = [
        {"asset_id": asset_ids[5],  "policy_id": policy_ids[5], "violation_type": "unencrypted_backup",    "severity": "high",     "description": "S3 Backup Bucket contains PCI/PII data but server-side encryption is disabled."},
        {"asset_id": asset_ids[4],  "policy_id": policy_ids[1], "violation_type": "encryption_gap",        "severity": "medium",   "description": "Analytics Data Lake raw zone retains PII without encryption at rest enabled."},
        {"asset_id": asset_ids[9],  "policy_id": policy_ids[3], "violation_type": "missing_audit_logging", "severity": "critical", "description": "Payments API v2 CloudTrail audit logging disabled for 3 API methods."},
    ]
    for v in violations_def:
        engine.log_violation(org_id, v)

    engine.add_data_flow(org_id, {"source_asset_id": asset_ids[0], "destination": "analytics-warehouse.internal", "flow_type": "internal",    "data_categories": ["PII"], "encrypted": True,  "approved": True})
    engine.add_data_flow(org_id, {"source_asset_id": asset_ids[1], "destination": "payment-processor.stripe.com", "flow_type": "external",    "data_categories": ["PCI"], "encrypted": True,  "approved": True})
    engine.add_data_flow(org_id, {"source_asset_id": asset_ids[0], "destination": "EU Analytics Partner (SFTP)",  "flow_type": "cross_border","data_categories": ["PII"], "encrypted": True,  "approved": False})

    stats = engine.get_governance_stats(org_id)
    return {"engine": "DataGovernanceEngine", "assets": stats["total_assets"],
            "policies": stats["total_policies"], "open_violations": stats["open_violations"]}


# ---------------------------------------------------------------------------
# 6. ComplianceScannerEngine
# ---------------------------------------------------------------------------

def seed_compliance(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 3 scan profiles, run a scan for each, add 8 remediation tasks."""
    from core.compliance_scanner_engine import ComplianceScannerEngine

    engine = ComplianceScannerEngine()

    if reset:
        import sqlite3
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute("DELETE FROM scan_profiles WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM scan_results WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM compliance_checks WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM remediation_tasks WHERE org_id=?", (org_id,))

    profiles_def = [
        {"name": "SOC2 + ISO27001 — Core Controls",  "frameworks": ["SOC2", "ISO27001"],   "scan_frequency_hours": 24},
        {"name": "NIST CSF + PCI DSS — Full Scope",  "frameworks": ["NIST_CSF", "PCI_DSS"],"scan_frequency_hours": 48},
        {"name": "HIPAA + GDPR — Privacy Bundle",    "frameworks": ["HIPAA", "GDPR"],       "scan_frequency_hours": 168},
    ]

    profiles = []
    for p in profiles_def:
        profiles.append(engine.create_profile(org_id, p))

    scan_results = []
    for profile in profiles:
        scan_results.append(engine.start_scan(org_id, profile["profile_id"]))

    # 8 remediation tasks
    task_defs = [
        {"title": "Enable MFA for all privileged accounts",           "priority": "critical","assigned_to": "identity@aldeci.io", "due_date": _date(days_ahead=3)},
        {"title": "Implement role-based access controls audit trail",  "priority": "high",    "assigned_to": "iam@aldeci.io",      "due_date": _date(days_ahead=7)},
        {"title": "Deploy SIEM alerting for CC7.2 detection rules",   "priority": "high",    "assigned_to": "soc@aldeci.io",      "due_date": _date(days_ahead=14)},
        {"title": "Conduct change management process review",          "priority": "medium",  "assigned_to": "grc@aldeci.io",      "due_date": _date(days_ahead=30)},
        {"title": "Remediate open TLS 1.0/1.1 configurations",        "priority": "high",    "assigned_to": "platform@aldeci.io", "due_date": _date(days_ahead=7)},
        {"title": "Document and test availability SLAs",               "priority": "medium",  "assigned_to": "sre@aldeci.io",      "due_date": _date(days_ahead=30)},
        {"title": "Implement network segmentation for payment zone",   "priority": "critical","assigned_to": "network@aldeci.io",  "due_date": _date(days_ahead=7)},
        {"title": "Run quarterly vulnerability scans (PCI Req-11.2)", "priority": "high",    "assigned_to": "vulnmgmt@aldeci.io", "due_date": _date(days_ahead=14)},
    ]

    tasks_created = 0
    if scan_results:
        first_result_id = scan_results[0]["result_id"]
        all_checks = (engine.list_checks(org_id, first_result_id, status="fail") +
                      engine.list_checks(org_id, first_result_id, status="warning"))
        for i, task_def in enumerate(task_defs):
            check_id = all_checks[i % len(all_checks)]["check_id"] if all_checks else "placeholder"
            task_def["description"] = f"Remediation for compliance check {check_id}"
            engine.create_remediation_task(org_id, check_id, task_def)
            tasks_created += 1

    stats = engine.get_compliance_stats(org_id)
    return {"engine": "ComplianceScannerEngine", "profiles": len(profiles),
            "scans_run": len(scan_results), "avg_score": stats["avg_score"],
            "remediation_tasks": tasks_created}


# ---------------------------------------------------------------------------
# 7. AssetRiskCalculator
# ---------------------------------------------------------------------------

def seed_asset_risk(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 15 assets with risk factors and calculated scores."""
    from core.asset_risk_calculator import AssetRiskCalculator

    engine = AssetRiskCalculator()

    if reset:
        import sqlite3
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute("DELETE FROM asset_profiles WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM risk_scores WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM risk_factors WHERE org_id=?", (org_id,))

    assets_def = [
        # 2 critical risk
        {"name": "prod-payments-db-01",   "asset_type": "database",       "criticality": "critical","exposure": "internet_facing","owner": "payments@aldeci.io",  "tags": ["pci","prod"],    "f": {"vuln_score": 88, "threat_score": 92, "exposure_score": 95, "compliance_score": 72}},
        {"name": "corp-dc-01 (AD DC)",    "asset_type": "server",         "criticality": "critical","exposure": "internal",       "owner": "it@aldeci.io",        "tags": ["ad","critical"], "f": {"vuln_score": 85, "threat_score": 88, "exposure_score": 70, "compliance_score": 65}},
        # 4 high risk
        {"name": "prod-web-lb-01",        "asset_type": "server",         "criticality": "high",    "exposure": "internet_facing","owner": "sre@aldeci.io",       "tags": ["prod","dmz"],    "f": {"vuln_score": 72, "threat_score": 68, "exposure_score": 90, "compliance_score": 75}},
        {"name": "ec2-k8s-worker-03",     "asset_type": "cloud_instance", "criticality": "high",    "exposure": "internal",       "owner": "platform@aldeci.io",  "tags": ["k8s","prod"],    "f": {"vuln_score": 68, "threat_score": 65, "exposure_score": 55, "compliance_score": 60}},
        {"name": "prod-kafka-01",         "asset_type": "server",         "criticality": "high",    "exposure": "internal",       "owner": "data@aldeci.io",      "tags": ["kafka","prod"],   "f": {"vuln_score": 62, "threat_score": 70, "exposure_score": 50, "compliance_score": 58}},
        {"name": "prod-redis-cluster",    "asset_type": "cloud_instance", "criticality": "high",    "exposure": "internal",       "owner": "platform@aldeci.io",  "tags": ["cache","prod"],   "f": {"vuln_score": 55, "threat_score": 72, "exposure_score": 45, "compliance_score": 62}},
        # 6 medium risk
        {"name": "dev-api-server-01",     "asset_type": "server",         "criticality": "medium",  "exposure": "internal",       "owner": "engineering@aldeci.io","tags": ["dev","api"],      "f": {"vuln_score": 45, "threat_score": 40, "exposure_score": 35, "compliance_score": 55}},
        {"name": "ec2-analytics-01",      "asset_type": "cloud_instance", "criticality": "medium",  "exposure": "internal",       "owner": "analytics@aldeci.io", "tags": ["analytics"],      "f": {"vuln_score": 38, "threat_score": 42, "exposure_score": 30, "compliance_score": 50}},
        {"name": "corp-file-server-02",   "asset_type": "server",         "criticality": "medium",  "exposure": "internal",       "owner": "it@aldeci.io",        "tags": ["files","corp"],   "f": {"vuln_score": 42, "threat_score": 38, "exposure_score": 25, "compliance_score": 48}},
        {"name": "staging-db-01",         "asset_type": "database",       "criticality": "medium",  "exposure": "internal",       "owner": "engineering@aldeci.io","tags": ["staging"],       "f": {"vuln_score": 35, "threat_score": 35, "exposure_score": 30, "compliance_score": 55}},
        {"name": "rds-reporting-01",      "asset_type": "database",       "criticality": "medium",  "exposure": "internal",       "owner": "bi@aldeci.io",        "tags": ["reporting"],      "f": {"vuln_score": 32, "threat_score": 33, "exposure_score": 28, "compliance_score": 58}},
        {"name": "iot-building-sensors",  "asset_type": "iot",            "criticality": "medium",  "exposure": "internal",       "owner": "facilities@aldeci.io","tags": ["iot","physical"], "f": {"vuln_score": 48, "threat_score": 30, "exposure_score": 35, "compliance_score": 40}},
        # 3 low risk
        {"name": "dev-workstation-eng-14","asset_type": "workstation",    "criticality": "low",     "exposure": "internal",       "owner": "hr@aldeci.io",        "tags": ["workstation"],    "f": {"vuln_score": 20, "threat_score": 18, "exposure_score": 15, "compliance_score": 62}},
        {"name": "qa-test-runner-02",     "asset_type": "server",         "criticality": "low",     "exposure": "internal",       "owner": "qa@aldeci.io",        "tags": ["qa","testing"],   "f": {"vuln_score": 18, "threat_score": 15, "exposure_score": 12, "compliance_score": 70}},
        {"name": "corp-printer-fleet",    "asset_type": "network_device", "criticality": "low",     "exposure": "internal",       "owner": "it@aldeci.io",        "tags": ["printer"],        "f": {"vuln_score": 22, "threat_score": 12, "exposure_score": 10, "compliance_score": 55}},
    ]

    assets_created = 0
    for a in assets_def:
        factors_raw = a.pop("f")
        asset = engine.register_asset(org_id, a)
        aid = asset["asset_id"]
        assets_created += 1

        for ftype, fkey in [("vulnerability","vuln_score"),("threat_intel","threat_score"),("exposure","exposure_score"),("compliance","compliance_score")]:
            engine.add_risk_factor(org_id, aid, {
                "factor_type": ftype,
                "factor_name": f"{ftype.title()} — {a['name']}",
                "impact":      factors_raw[fkey] / 10.0,
                "description": f"Auto-assessed {ftype} score",
            })

        engine.calculate_risk(org_id, aid, [factors_raw])

    stats = engine.get_risk_stats(org_id)
    return {"engine": "AssetRiskCalculator", "assets": assets_created,
            "by_risk_level": stats["by_risk_level"],
            "avg_composite_score": stats["avg_composite_score"]}


# ---------------------------------------------------------------------------
# 8. SecurityHealthEngine
# ---------------------------------------------------------------------------

def seed_health(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 14 health checks, run snapshot, log 2 open incidents."""
    from core.security_health_engine import SecurityHealthEngine

    engine = SecurityHealthEngine()

    if reset:
        import sqlite3
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute("DELETE FROM health_checks WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM health_incidents WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM health_snapshots WHERE org_id=?", (org_id,))

    checks_def = [
        {"check_name": "Firewall ruleset compliance",          "category": "network",      "status": "healthy",  "score": 91, "details": "208 active rules; 100% CIS compliant.",                          "check_interval_hours": 24},
        {"check_name": "Network segmentation coverage",        "category": "network",      "status": "healthy",  "score": 87, "details": "VLANs correctly segmented; no lateral paths detected.",          "check_interval_hours": 24},
        {"check_name": "EDR agent coverage",                   "category": "endpoint",     "status": "degraded", "score": 74, "details": "EDR on 93% of endpoints. 47 devices missing — SEC-1204.",       "check_interval_hours": 12},
        {"check_name": "Patch compliance — OS",                "category": "endpoint",     "status": "healthy",  "score": 85, "details": "94% fully patched; critical patches within SLA.",                "check_interval_hours": 24},
        {"check_name": "MFA enrollment rate",                  "category": "identity",     "status": "healthy",  "score": 96, "details": "MFA enabled on 98.7% of accounts.",                             "check_interval_hours": 24},
        {"check_name": "Privileged account governance",        "category": "identity",     "status": "healthy",  "score": 88, "details": "42 privileged accounts reviewed; JIT enforced for prod.",        "check_interval_hours": 48},
        {"check_name": "Cloud misconfiguration score (CSPM)",  "category": "cloud",        "status": "critical", "score": 52, "details": "CRITICAL: 3 S3 buckets public-read, 2 SGs 0.0.0.0/0 — SEC-1198.","check_interval_hours": 6},
        {"check_name": "Cloud IAM entitlement hygiene",        "category": "cloud",        "status": "healthy",  "score": 82, "details": "Excess permissions pruned for 23 roles. No wildcard in prod.",   "check_interval_hours": 24},
        {"check_name": "Data encryption at rest coverage",     "category": "data",         "status": "healthy",  "score": 89, "details": "91% encrypted; 2 legacy DBs pending migration.",                 "check_interval_hours": 48},
        {"check_name": "DLP policy enforcement rate",          "category": "data",         "status": "degraded", "score": 68, "details": "DLP active on 78% of egress channels; Teams excluded.",          "check_interval_hours": 24},
        {"check_name": "DAST scan coverage",                   "category": "application",  "status": "healthy",  "score": 83, "details": "All 34 API routers DAST-covered. Last scan: 2025-04-13.",       "check_interval_hours": 24},
        {"check_name": "Secret rotation compliance",           "category": "application",  "status": "healthy",  "score": 92, "details": "API keys rotated per 90d policy. No plaintext secrets in repos.","check_interval_hours": 24},
        {"check_name": "SOC2 control test completion",         "category": "compliance",   "status": "healthy",  "score": 88, "details": "87 of 100 SOC2 controls tested.",                               "check_interval_hours": 168},
        {"check_name": "Vulnerability SLA adherence",          "category": "compliance",   "status": "healthy",  "score": 85, "details": "94% of critical vulns remediated within 7-day SLA.",             "check_interval_hours": 24},
    ]

    check_ids = []
    for c in checks_def:
        check = engine.register_check(org_id, c)
        check_ids.append(check["check_id"])

    snapshot = engine.run_health_snapshot(org_id)

    engine.log_incident(org_id, check_ids[6], {
        "title": "CRITICAL: Public S3 Buckets + Open Security Groups",
        "description": "CSPM detected 3 public S3 buckets and 2 SGs with 0.0.0.0/0. Immediate action required.",
        "severity": "critical",
    })
    engine.log_incident(org_id, check_ids[2], {
        "title": "EDR Coverage Gap — 47 Unprotected Endpoints",
        "description": "47 endpoints missing EDR. 12 in finance segment. Ticket: SEC-1204.",
        "severity": "high",
    })

    stats = engine.get_health_stats(org_id)
    return {"engine": "SecurityHealthEngine", "checks": len(checks_def),
            "overall_score": snapshot["overall_score"],
            "open_incidents": stats["open_incidents"]}


# ---------------------------------------------------------------------------
# 9. IncidentTimelineEngine
# ---------------------------------------------------------------------------

def seed_timelines(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 3 timelines: active ransomware, resolved phishing, closed insider."""
    from core.incident_timeline_engine import IncidentTimelineEngine

    engine = IncidentTimelineEngine()

    if reset:
        import sqlite3
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute("DELETE FROM timelines WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM timeline_events WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM affected_systems WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM timeline_metrics WHERE org_id=?", (org_id,))

    # --- Timeline 1: Active ransomware ---
    t1 = engine.create_timeline(org_id, {
        "title": "BlackCat Ransomware — Finance Cluster (INC-2025-0041)",
        "incident_type": "ransomware", "severity": "critical", "started_at": _ts(days_ago=3),
        "summary": "BlackCat encrypted 14 servers. Initial access via phishing; lateral movement via Mimikatz.",
    })
    t1_id = t1["timeline_id"]
    for ev in [
        {"event_type": "detection",   "title": "Unusual file extension changes detected by EDR",        "description": "CrowdStrike Falcon detected mass .locked file creation at 02:14 UTC.",              "actor": "CrowdStrike EDR", "source_system": "Falcon",      "severity": "critical","event_time": _ts(days_ago=3,hours_ago=20)},
        {"event_type": "alert",       "title": "SIEM correlation: Ransomware pattern (sigma rule)",     "description": "ALDECI SIEM correlated 14 alerts into single high-confidence ransomware campaign.",   "actor": "ALDECI SIEM",     "source_system": "Elastic",     "severity": "critical","event_time": _ts(days_ago=3,hours_ago=19)},
        {"event_type": "escalation",  "title": "CISO + IR team paged",                                 "description": "SOC escalated to CISO. IR retainer activated.",                                       "actor": "SOC L2",          "source_system": "PagerDuty",   "severity": "critical","event_time": _ts(days_ago=3,hours_ago=18)},
        {"event_type": "action",      "title": "Finance cluster isolated — network quarantine applied", "description": "14 affected servers isolated at switch level. Finance VPC egress blocked.",           "actor": "Network Team",    "source_system": "Cisco",       "severity": "critical","event_time": _ts(days_ago=3,hours_ago=17)},
        {"event_type": "communication","title": "Executive briefing — CEO + Legal notified",            "description": "Situation report delivered. Regulatory notification timeline started.",               "actor": "CISO",            "source_system": "Zoom",        "severity": "high",   "event_time": _ts(days_ago=3,hours_ago=16)},
        {"event_type": "action",      "title": "Forensic imaging of 14 servers initiated",             "description": "Evidence collection per NIST SP 800-86. 14 disk images + memory dumps.",               "actor": "alice@aldeci.io", "source_system": "FTK Imager",  "severity": "high",   "event_time": _ts(days_ago=2,hours_ago=22)},
        {"event_type": "containment", "title": "Clean restore from backup for 8 servers initiated",    "description": "8 servers restored from last clean snapshot. Finance ops partially restored.",         "actor": "Cloud Ops",       "source_system": "AWS Backup",  "severity": "high",   "event_time": _ts(days_ago=2,hours_ago=10)},
        {"event_type": "action",      "title": "All finance user passwords reset + MFA re-enrolled",   "description": "1,200 finance user passwords force-reset. MFA tokens revoked and re-issued.",         "actor": "Identity Team",   "source_system": "Okta",        "severity": "high",   "event_time": _ts(days_ago=1,hours_ago=12)},
    ]:
        engine.add_event(org_id, t1_id, ev)
    for sys_d in [
        {"hostname": "finance-srv-01","ip_address": "10.10.1.101","system_type": "Windows Server 2022","impact_description": "Fully encrypted — 48,000 files affected"},
        {"hostname": "finance-srv-02","ip_address": "10.10.1.102","system_type": "Windows Server 2022","impact_description": "Fully encrypted — 52,000 files affected"},
        {"hostname": "finance-db-01", "ip_address": "10.10.1.150","system_type": "SQL Server 2019",    "impact_description": "DB files encrypted — read-only mode"},
        {"hostname": "finance-app-01","ip_address": "10.10.1.201","system_type": "Windows Server 2019","impact_description": "Application tier encrypted"},
    ]:
        engine.add_affected_system(org_id, t1_id, sys_d)
    engine.calculate_metrics(org_id, t1_id)

    # --- Timeline 2: Resolved phishing ---
    t2 = engine.create_timeline(org_id, {
        "title": "Executive Spear-Phishing — CFO Credential Compromise (INC-2025-0033)",
        "incident_type": "phishing", "severity": "high", "started_at": _ts(days_ago=14),
        "summary": "CFO credentials stolen via Evilginx2 AiTM kit. Attacker accessed email 4 hours. No wire transfers.",
    })
    t2_id = t2["timeline_id"]
    for ev in [
        {"event_type": "detection",     "title": "Impossible travel alert — CFO login Kyiv + NYC",     "description": "SIEM: CFO logged in from UA (185.220.101.47) and NYC within 45 min.",              "actor": "ALDECI SIEM", "source_system": "Elastic","severity": "high",  "event_time": _ts(days_ago=14,hours_ago=20)},
        {"event_type": "alert",         "title": "SOC confirmed AiTM phishing — OAuth tokens stolen",  "description": "Credential theft via Evilginx2 confirmed. OAuth refresh tokens also stolen.",       "actor": "SOC L1",     "source_system": "Splunk", "severity": "high",  "event_time": _ts(days_ago=14,hours_ago=19)},
        {"event_type": "action",        "title": "CFO session terminated + all tokens revoked",         "description": "All CFO sessions terminated. OAuth refresh tokens revoked in Okta.",                "actor": "IdP Team",   "source_system": "Okta",   "severity": "high",  "event_time": _ts(days_ago=14,hours_ago=18)},
        {"event_type": "containment",   "title": "Email quarantine — phishing variants removed",        "description": "135 similar phishing emails quarantined. Defender for O365 rule deployed.",        "actor": "Email Sec",  "source_system": "Defender","severity": "medium","event_time": _ts(days_ago=14,hours_ago=17)},
        {"event_type": "eradication",   "title": "Attacker infrastructure blocked at perimeter",        "description": "8 attacker IPs + 3 domains added to blocklist and TI platform.",                   "actor": "Network",    "source_system": "PAN",    "severity": "medium","event_time": _ts(days_ago=14,hours_ago=16)},
        {"event_type": "recovery",      "title": "CFO access restored with FIDO2 hardware key",         "description": "CFO re-enrolled with YubiKey FIDO2. Conditional access policy updated for execs.", "actor": "IdP Team",   "source_system": "Okta",   "severity": "low",   "event_time": _ts(days_ago=13,hours_ago=22)},
        {"event_type": "lesson_learned","title": "Post-incident review — exec phishing playbook updated","description": "FIDO2 mandated for exec accounts. Awareness training scheduled.",                 "actor": "CISO",       "source_system": "Confluence","severity": "low", "event_time": _ts(days_ago=10,hours_ago=10)},
    ]:
        engine.add_event(org_id, t2_id, ev)
    engine.add_affected_system(org_id, t2_id, {"hostname": "cfo-laptop-01","ip_address": "10.0.5.22","system_type": "MacBook Pro","impact_description": "Email access compromised for 4 hours"})
    engine.update_timeline_status(org_id, t2_id, "resolved")
    engine.calculate_metrics(org_id, t2_id)

    # --- Timeline 3: Closed insider ---
    t3 = engine.create_timeline(org_id, {
        "title": "Insider Exfiltration — Departing Sales Engineer (INC-2025-0038)",
        "incident_type": "insider", "severity": "high", "started_at": _ts(days_ago=21),
        "summary": "SE uploaded 7.2 GB customer PII to personal Dropbox over 3 weeks. 4,200 records exposed.",
    })
    t3_id = t3["timeline_id"]
    for ev in [
        {"event_type": "detection",     "title": "DLP alert — large upload to personal cloud storage",   "description": "ALDECI DLP flagged 2.4 GB upload to dropbox.com from SE workstation.",            "actor": "ALDECI DLP",  "source_system": "DLP",       "severity": "high",  "event_time": _ts(days_ago=21,hours_ago=14)},
        {"event_type": "alert",         "title": "UEBA anomaly: 300% increase in file access",            "description": "UEBA detected 300% spike in file access vs 90-day baseline.",                     "actor": "UEBA Engine", "source_system": "UEBA",      "severity": "high",  "event_time": _ts(days_ago=20,hours_ago=10)},
        {"event_type": "escalation",    "title": "HR + Legal notified — covert investigation started",    "description": "Evidence-preservation hold placed on mailbox, OneDrive, endpoint.",               "actor": "IR Lead",     "source_system": "Exchange",  "severity": "high",  "event_time": _ts(days_ago=20,hours_ago=8)},
        {"event_type": "action",        "title": "Forensic imaging of SE workstation",                    "description": "Disk image + memory dump collected. Chain of custody established.",                "actor": "bob@aldeci.io","source_system": "FTK",      "severity": "medium","event_time": _ts(days_ago=19,hours_ago=12)},
        {"event_type": "action",        "title": "Employee terminated — all access revoked",              "description": "AD, SaaS, VPN, badge access revoked.",                                           "actor": "HR + IT",     "source_system": "Okta + AD", "severity": "medium","event_time": _ts(days_ago=17,hours_ago=9)},
        {"event_type": "eradication",   "title": "Customer notification — GDPR Art. 34 (72h window)",    "description": "4,200 customers notified. DPA notified within 72-hour GDPR window.",              "actor": "Legal + DPO", "source_system": "Notify",    "severity": "high",  "event_time": _ts(days_ago=14,hours_ago=10)},
        {"event_type": "lesson_learned","title": "DLP + offboarding checklist updated",                   "description": "Dropbox blocked for non-approved users. Offboarding includes DLP review trigger.","actor": "CISO",        "source_system": "Confluence","severity": "low",   "event_time": _ts(days_ago=10,hours_ago=9)},
        {"event_type": "lesson_learned","title": "USB + personal cloud storage blocked via MDM",          "description": "USB mass storage and unapproved cloud storage blocked via Intune for all users.", "actor": "IT Security", "source_system": "Intune",    "severity": "low",   "event_time": _ts(days_ago=8,hours_ago=14)},
    ]:
        engine.add_event(org_id, t3_id, ev)
    engine.add_affected_system(org_id, t3_id, {"hostname": "se-workstation-07","ip_address": "10.0.8.55","system_type": "Windows 11","impact_description": "4,200 customer records exfiltrated"})
    engine.update_timeline_status(org_id, t3_id, "resolved")
    engine.update_timeline_status(org_id, t3_id, "closed")
    engine.calculate_metrics(org_id, t3_id)

    stats = engine.get_timeline_stats(org_id)
    return {"engine": "IncidentTimelineEngine", "timelines": stats["total_timelines"],
            "active": stats["active_incidents"], "resolved": stats["resolved_incidents"]}


# ---------------------------------------------------------------------------
# 10. VulnTrendEngine
# ---------------------------------------------------------------------------

def seed_vuln_trends(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 6 monthly snapshots, trend analysis, and 8 SLA-tracked vulns."""
    from core.vuln_trend_engine import VulnTrendEngine

    engine = VulnTrendEngine()

    if reset:
        import sqlite3
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute("DELETE FROM vuln_snapshots WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM vuln_trends WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM sla_tracking WHERE org_id=?", (org_id,))
            conn.execute("DELETE FROM vuln_cohorts WHERE org_id=?", (org_id,))

    # 6 monthly snapshots — improving trend (critical declining)
    snapshots = [
        {"month_ago": 5, "total_vulns": 847, "critical": 23, "high": 182, "medium": 412, "low": 215, "info": 15, "mttr_days": 48.2, "new_this_week": 34, "resolved_this_week": 22, "sla_breached": 8},
        {"month_ago": 4, "total_vulns": 792, "critical": 19, "high": 165, "medium": 398, "low": 197, "info": 13, "mttr_days": 44.1, "new_this_week": 28, "resolved_this_week": 31, "sla_breached": 6},
        {"month_ago": 3, "total_vulns": 731, "critical": 15, "high": 148, "medium": 374, "low": 181, "info": 13, "mttr_days": 39.7, "new_this_week": 25, "resolved_this_week": 38, "sla_breached": 5},
        {"month_ago": 2, "total_vulns": 668, "critical": 12, "high": 131, "medium": 341, "low": 174, "info": 10, "mttr_days": 34.3, "new_this_week": 21, "resolved_this_week": 42, "sla_breached": 3},
        {"month_ago": 1, "total_vulns": 603, "critical":  9, "high": 118, "medium": 308, "low": 162, "info":  6, "mttr_days": 29.8, "new_this_week": 18, "resolved_this_week": 45, "sla_breached": 2},
        {"month_ago": 0, "total_vulns": 541, "critical":  7, "high": 104, "medium": 281, "low": 144, "info":  5, "mttr_days": 26.4, "new_this_week": 15, "resolved_this_week": 47, "sla_breached": 1},
    ]

    for snap in snapshots:
        days_ago = snap.pop("month_ago") * 30
        snap["taken_at"] = _ts(days_ago=days_ago)
        engine.record_snapshot(org_id, snap)

    engine.get_trend_analysis(org_id)

    sla_vulns = [
        {"vuln_id": "CVE-2025-0282",  "severity": "critical", "discovered_at": _ts(days_ago=5)},
        {"vuln_id": "CVE-2024-49138", "severity": "critical", "discovered_at": _ts(days_ago=10)},
        {"vuln_id": "CVE-2025-1102",  "severity": "high",     "discovered_at": _ts(days_ago=8)},
        {"vuln_id": "CVE-2024-55956", "severity": "high",     "discovered_at": _ts(days_ago=12)},
        {"vuln_id": "CVE-2025-0234",  "severity": "high",     "discovered_at": _ts(days_ago=15)},
        {"vuln_id": "CVE-2024-38021", "severity": "medium",   "discovered_at": _ts(days_ago=45)},
        {"vuln_id": "CVE-2024-21413", "severity": "medium",   "discovered_at": _ts(days_ago=60)},
        {"vuln_id": "CVE-2023-44487", "severity": "low",      "discovered_at": _ts(days_ago=120)},
    ]
    for v in sla_vulns:
        engine.track_sla(org_id, v)

    engine.create_cohort(org_id, {"cohort_name": "Critical — Q1 2025 Unpatched",   "vuln_ids": ["CVE-2025-0282", "CVE-2024-49138"],               "avg_age_days": 7.5,  "avg_cvss": 9.4})
    engine.create_cohort(org_id, {"cohort_name": "High — Legacy OS Components",     "vuln_ids": ["CVE-2025-1102", "CVE-2024-55956", "CVE-2025-0234"],"avg_age_days": 11.7, "avg_cvss": 7.8})
    engine.create_cohort(org_id, {"cohort_name": "Medium — Web Application",        "vuln_ids": ["CVE-2024-38021", "CVE-2024-21413"],              "avg_age_days": 52.5, "avg_cvss": 6.2})

    stats = engine.get_trend_stats(org_id)
    return {"engine": "VulnTrendEngine", "snapshots": stats["snapshots_count"],
            "active_slas": stats["active_slas"], "overall_trend": stats["overall_trend"],
            "avg_critical": stats["avg_critical"]}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ALDECI Demo Data Seeder — seeds investor-quality demo data into all engines."
    )
    parser.add_argument("--org-id", default="aldeci-demo",
                        help="Org ID for demo data (default: aldeci-demo)")
    parser.add_argument("--reset", action="store_true",
                        help="Clear existing demo data for this org before seeding")
    args = parser.parse_args()

    org_id = args.org_id
    reset  = args.reset

    print(f"\nALDECI Demo Data Seeder")
    print(f"  Org ID : {org_id}")
    print(f"  Reset  : {reset}")
    print(f"  Time   : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

    seeders = [
        ("Posture Score Engine",      lambda r: seed_posture(org_id, r)),
        ("Threat Feed Aggregator",    lambda r: seed_threat_feeds(org_id, r)),
        ("Digital Forensics Engine",  lambda r: seed_forensics(org_id, r)),
        ("Security Roadmap Engine",   lambda r: seed_roadmap(org_id, r)),
        ("Data Governance Engine",    lambda r: seed_data_governance(org_id, r)),
        ("Compliance Scanner Engine", lambda r: seed_compliance(org_id, r)),
        ("Asset Risk Calculator",     lambda r: seed_asset_risk(org_id, r)),
        ("Security Health Engine",    lambda r: seed_health(org_id, r)),
        ("Incident Timeline Engine",  lambda r: seed_timelines(org_id, r)),
        ("Vuln Trend Engine",         lambda r: seed_vuln_trends(org_id, r)),
    ]

    ok = skip = fail = 0
    for name, fn in seeders:
        try:
            result = fn(reset)
            ok += 1
            summary = ", ".join(f"{k}={v}" for k, v in result.items() if k != "engine")
            print(f"  [OK]   {name}: {summary}")
        except ImportError as exc:
            skip += 1
            print(f"  [SKIP] {name}: module not installed — {exc}")
        except Exception as exc:
            fail += 1
            print(f"  [FAIL] {name}: {exc}")

    print(f"\n  Seeded {ok}/{len(seeders)} engines  ({skip} skipped, {fail} failed)")
    print(f"\nDemo data ready. Org ID: {org_id}")
    print(f"Access platform at: http://localhost:8000\n")


if __name__ == "__main__":
    main()
