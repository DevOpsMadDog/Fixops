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
# 11. CyberInsuranceEngine
# ---------------------------------------------------------------------------

def seed_cyber_insurance(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 3 insurance policies with assessments and claims."""
    try:
        from core.cyber_insurance_engine import CyberInsuranceEngine
    except ImportError as exc:
        return {"engine": "CyberInsuranceEngine", "error": str(exc)}

    engine = CyberInsuranceEngine()

    policies_def = [
        {
            "carrier": "Lloyd's of London",
            "policy_number": "LLY-CYB-2025-00142",
            "coverage_type": "both",
            "coverage_limit": 10_000_000.0,
            "deductible": 100_000.0,
            "premium_annual": 285_000.0,
            "effective_date": _date(days_ago=180),
            "expiry_date": _date(days_ahead=185),
            "status": "active",
            "covered_events": ["ransomware", "data_breach", "business_interruption",
                               "social_engineering", "network_failure"],
        },
        {
            "carrier": "AIG CyberEdge",
            "policy_number": "AIG-CE-2024-87631",
            "coverage_type": "first_party",
            "coverage_limit": 5_000_000.0,
            "deductible": 50_000.0,
            "premium_annual": 142_000.0,
            "effective_date": _date(days_ago=300),
            "expiry_date": _date(days_ago=30),
            "status": "expired",
            "covered_events": ["ransomware", "business_interruption"],
        },
        {
            "carrier": "Chubb Cyber Enterprise Risk Management",
            "policy_number": "CHB-CERM-2025-00451",
            "coverage_type": "third_party",
            "coverage_limit": 3_000_000.0,
            "deductible": 25_000.0,
            "premium_annual": 98_000.0,
            "effective_date": _date(days_ahead=30),
            "expiry_date": _date(days_ahead=395),
            "status": "pending",
            "covered_events": ["data_breach", "social_engineering"],
        },
    ]

    policy_ids = []
    for p in policies_def:
        result = engine.add_policy(org_id, p)
        policy_ids.append(result["policy_id"])

    # Coverage assessment for active policy
    engine.create_assessment(org_id, policy_ids[0], {
        "mfa_score": 88,
        "backup_score": 92,
        "incident_response_score": 79,
        "patch_score": 74,
        "training_score": 85,
        "recommendations": [
            "Enable FIDO2 hardware keys for all privileged accounts",
            "Reduce patch SLA for critical CVEs from 30 to 7 days",
            "Conduct tabletop exercise with insurer within 90 days",
        ],
        "assessed_at": _ts(days_ago=14),
    })

    # File one active claim on the expired AIG policy
    engine.file_claim(org_id, {
        "policy_id": policy_ids[1],
        "incident_type": "ransomware",
        "incident_date": _ts(days_ago=90),
        "estimated_loss": 1_250_000.0,
        "adjuster": "James Thornton (AIG CyberEdge Claims)",
    })

    policies = engine.list_policies(org_id)
    claims = engine.list_claims(org_id)
    return {"engine": "CyberInsuranceEngine",
            "policies": len(policies), "claims": len(claims)}


# ---------------------------------------------------------------------------
# 12. ExecutiveReportingEngine
# ---------------------------------------------------------------------------

def seed_executive_reporting(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed board reports, KPIs, and a board presentation."""
    try:
        from core.executive_reporting_engine import ExecutiveReportingEngine
    except ImportError as exc:
        return {"engine": "ExecutiveReportingEngine", "error": str(exc)}

    engine = ExecutiveReportingEngine()

    # Monthly report (published)
    monthly = engine.create_report(org_id, {
        "report_type": "monthly",
        "title": "ALDECI Security Report — April 2026",
        "period_start": _date(days_ago=30),
        "period_end": _date(),
        "created_by": "ciso@aldeci.io",
        "sections": [
            {"title": "Executive Summary",     "content": "Overall security posture improved by 3 points to 74/100 (Grade C). Zero critical incidents. Patch cadence ahead of SLA targets."},
            {"title": "Threat Landscape",      "content": "APT41 supply-chain campaign active. 14 KEV vulns addressed this month. Phishing attempt rate down 18% vs March."},
            {"title": "Vulnerability Metrics", "content": "541 open vulns (down from 603). Critical: 7 (down from 9). MTTR critical: 4.2 days (SLA: 7 days). 100% SLA compliance."},
            {"title": "Compliance Posture",    "content": "SOC 2 Type II readiness at 87%. PCI-DSS gap assessment complete. ISO 27001 surveillance audit passed."},
            {"title": "Upcoming Actions",      "content": "Zero Trust Phase 2 pilot (prod zone A) launching May 1. Board presentation scheduled May 15."},
        ],
    })
    report_id = monthly["id"]

    for metric in [
        {"metric_name": "Mean Time to Detect (MTTD)", "metric_value": 2.4,  "metric_unit": "hours",   "trend": "down", "comparison_value": 3.1,  "comparison_period": "March 2026", "narrative": "Improved correlation rules in SIEM reduced detection time by 23%."},
        {"metric_name": "Mean Time to Respond (MTTR)", "metric_value": 4.2, "metric_unit": "hours",   "trend": "down", "comparison_value": 5.8,  "comparison_period": "March 2026", "narrative": "SOAR playbook automation reduced manual IR steps by 40%."},
        {"metric_name": "Critical Vulnerabilities",    "metric_value": 7,   "metric_unit": "count",   "trend": "down", "comparison_value": 9,    "comparison_period": "March 2026", "narrative": "2 critical CVEs patched. Remaining 7 in 4-day remediation window."},
        {"metric_name": "Security Posture Score",      "metric_value": 74,  "metric_unit": "score",   "trend": "up",   "comparison_value": 71,   "comparison_period": "March 2026", "narrative": "Identity security and training scores drove 3-point improvement."},
        {"metric_name": "Phishing Click Rate",         "metric_value": 4.2, "metric_unit": "percent", "trend": "down", "comparison_value": 5.1,  "comparison_period": "March 2026", "narrative": "Phishing simulation campaign with targeted re-training delivered 18% improvement."},
        {"metric_name": "Patch Compliance Rate",       "metric_value": 94.7,"metric_unit": "percent", "trend": "up",   "comparison_value": 91.2, "comparison_period": "March 2026", "narrative": "Automated patch orchestration deployed to 850 endpoints."},
    ]:
        engine.add_metric(org_id, report_id, metric)

    engine.publish_report(org_id, report_id)

    # Quarterly board report (draft)
    engine.create_report(org_id, {
        "report_type": "board",
        "title": "Q1 2026 Board Security Briefing",
        "period_start": "2026-01-01",
        "period_end": "2026-03-31",
        "created_by": "ciso@aldeci.io",
        "sections": [
            {"title": "Risk Posture Summary",  "content": "Posture score improved from 58 (F) to 71 (C) over Q1. 3 critical incidents, all resolved within SLA. No regulatory fines or breaches."},
            {"title": "Investment ROI",        "content": "Security tooling consolidated: $420K annual savings vs prior vendor stack. Incident cost avoidance estimated at $2.1M (ransomware prevention)."},
            {"title": "Regulatory Readiness",  "content": "SOC 2 Type II on track for Q3 certification. GDPR DPA audit passed in February. PCI-DSS gap assessment complete."},
            {"title": "Strategic Roadmap",     "content": "Zero Trust Phase 2 on schedule. Insider Threat Detection Program launching Q2. SBOM generation live for all containerised services."},
        ],
    })

    # KPIs
    kpi_defs = [
        ("Security Posture Score",         74.0,  80.0,  "score",   "improving"),
        ("MTTD (Mean Time to Detect)",      2.4,   4.0,   "hours",   "improving"),
        ("MTTR (Mean Time to Respond)",     4.2,   8.0,   "hours",   "improving"),
        ("Patch SLA Compliance",           94.7,  95.0,  "percent", "improving"),
        ("Phishing Click Rate",             4.2,   5.0,   "percent", "improving"),
        ("MFA Adoption Rate",              97.3,  100.0, "percent", "stable"),
        ("Critical Vulns Open",             7.0,   0.0,   "count",   "improving"),
        ("SOC 2 Readiness Score",          87.0,  100.0, "percent", "improving"),
    ]
    for kpi_name, value, target, unit, trend in kpi_defs:
        engine.set_kpi(org_id, kpi_name, value, target, unit, trend)

    # Board presentation
    engine.create_board_presentation(org_id, {
        "title": "ALDECI Board Security Briefing — May 2026",
        "presentation_date": _date(days_ahead=29),
        "audience": "board",
        "risk_summary": "Security posture at 74/100, trending +16 points YTD. No material breaches. Zero Trust architecture 35% deployed. Cyber insurance renewed with Lloyd's at $10M coverage.",
        "key_metrics": {
            "posture_score": 74,
            "critical_vulns": 7,
            "mttd_hours": 2.4,
            "mttr_hours": 4.2,
            "patch_compliance_pct": 94.7,
            "mfa_adoption_pct": 97.3,
        },
        "action_items": [
            "Approve $450K Zero Trust Phase 2 budget (due May 20)",
            "Review and sign cyber insurance renewal (Lloyd's — due June 1)",
            "Endorse SOC 2 Type II external audit engagement (Q3 target)",
            "Acknowledge updated IR Tabletop exercise findings",
        ],
    })

    reports = engine.list_reports(org_id)
    presentations = engine.list_board_presentations(org_id)
    return {"engine": "ExecutiveReportingEngine",
            "reports": len(reports), "kpis": len(kpi_defs),
            "board_presentations": len(presentations)}


# ---------------------------------------------------------------------------
# 13. CloudComplianceEngine
# ---------------------------------------------------------------------------

def seed_cloud_compliance(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed CIS AWS + Azure assessments with control results."""
    try:
        from core.cloud_compliance_engine import CloudComplianceEngine, _db_path_for_org
    except ImportError as exc:
        return {"engine": "CloudComplianceEngine", "error": str(exc)}

    engine = CloudComplianceEngine(db_path=_db_path_for_org(org_id))

    # AWS CIS v1.5 assessment
    aws_assessment = engine.create_assessment(org_id, {
        "cloud_provider": "aws",
        "framework": "cis_aws_v1.5",
        "scope": {"accounts": ["123456789012", "234567890123"],
                  "regions": ["us-east-1", "us-west-2", "eu-west-1"]},
        "total_controls": 58,
    })
    aws_id = aws_assessment["id"]

    aws_controls = [
        # Identity & Access
        {"control_id": "1.1",  "control_name": "Avoid the use of the root account",                  "section": "IAM", "severity": "critical", "status": "passed",   "resource_type": "aws::iam::rootaccount",    "resource_id": "root", "evidence": "Root account has no active access keys. MFA enabled.", "remediation": ""},
        {"control_id": "1.5",  "control_name": "Ensure MFA is enabled for the root account",         "section": "IAM", "severity": "critical", "status": "passed",   "resource_type": "aws::iam::rootaccount",    "resource_id": "root", "evidence": "Virtual MFA device attached to root account.", "remediation": ""},
        {"control_id": "1.10", "control_name": "Ensure MFA is enabled for all IAM users with console access", "section": "IAM", "severity": "high", "status": "failed", "resource_type": "aws::iam::user", "resource_id": "svc-deploy-user", "evidence": "3 IAM users with console access lack MFA.", "remediation": "Enable MFA for all console-access IAM users via IAM console or CLI."},
        {"control_id": "1.14", "control_name": "Ensure access keys are rotated every 90 days",       "section": "IAM", "severity": "high",     "status": "failed",   "resource_type": "aws::iam::accesskey",      "resource_id": "AKIAIOSFODNN7EXAMPLE", "evidence": "Key age: 127 days.", "remediation": "Rotate access keys. Update CI/CD secrets."},
        {"control_id": "1.16", "control_name": "Ensure IAM policies are attached only to groups or roles", "section": "IAM", "severity": "medium", "status": "passed", "resource_type": "aws::iam::user", "resource_id": "*", "evidence": "No direct user policy attachments found.", "remediation": ""},
        # Logging
        {"control_id": "2.1",  "control_name": "Ensure CloudTrail is enabled in all regions",        "section": "Logging", "severity": "critical", "status": "passed", "resource_type": "aws::cloudtrail::trail", "resource_id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/aldeci-prod", "evidence": "Multi-region trail enabled with log validation.", "remediation": ""},
        {"control_id": "2.2",  "control_name": "Ensure CloudTrail log file validation is enabled",   "section": "Logging", "severity": "high",     "status": "passed", "resource_type": "aws::cloudtrail::trail", "resource_id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/aldeci-prod", "evidence": "LogFileValidationEnabled: true", "remediation": ""},
        {"control_id": "2.6",  "control_name": "Ensure S3 bucket access logging is enabled on CloudTrail bucket", "section": "Logging", "severity": "medium", "status": "failed", "resource_type": "aws::s3::bucket", "resource_id": "aldeci-cloudtrail-logs", "evidence": "Access logging not configured.", "remediation": "Enable S3 access logging for the CloudTrail bucket."},
        # Networking
        {"control_id": "4.1",  "control_name": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", "section": "Networking", "severity": "critical", "status": "failed", "resource_type": "aws::ec2::securitygroup", "resource_id": "sg-0abc1234def56789a", "resource_name": "legacy-bastion-sg", "region": "us-east-1", "evidence": "Inbound rule: 0.0.0.0/0:22 found.", "remediation": "Restrict SSH to VPN CIDR 10.0.0.0/8 or use Systems Manager Session Manager."},
        {"control_id": "4.2",  "control_name": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", "section": "Networking", "severity": "critical", "status": "passed", "resource_type": "aws::ec2::securitygroup", "resource_id": "*", "evidence": "No security groups allow 0.0.0.0/0:3389.", "remediation": ""},
        {"control_id": "4.3",  "control_name": "Ensure VPC flow logging is enabled in all VPCs",    "section": "Networking", "severity": "medium", "status": "passed", "resource_type": "aws::ec2::vpc", "resource_id": "vpc-0a1b2c3d4e5f67890", "evidence": "Flow logs enabled to CloudWatch Logs.", "remediation": ""},
        # Storage
        {"control_id": "2.1.1","control_name": "Ensure all S3 buckets employ encryption-at-rest",   "section": "Storage", "severity": "high",   "status": "passed",   "resource_type": "aws::s3::bucket", "resource_id": "aldeci-data-prod", "evidence": "SSE-KMS enabled with CMK.", "remediation": ""},
        {"control_id": "2.1.2","control_name": "Ensure S3 Bucket Policy is set to deny HTTP requests","section": "Storage","severity": "medium",  "status": "failed",  "resource_type": "aws::s3::bucket", "resource_id": "aldeci-assets-cdn", "evidence": "Bucket policy does not enforce HTTPS.", "remediation": "Add bucket policy condition aws:SecureTransport=false Deny."},
    ]

    for ctrl in aws_controls:
        engine.add_control_result(org_id, aws_id, ctrl)

    # Azure CIS v1.5 assessment
    az_assessment = engine.create_assessment(org_id, {
        "cloud_provider": "azure",
        "framework": "cis_azure_v1.5",
        "scope": {"subscriptions": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
                  "regions": ["eastus", "westeurope"]},
        "total_controls": 42,
    })
    az_id = az_assessment["id"]

    az_controls = [
        {"control_id": "1.1",  "control_name": "Ensure that multi-factor authentication is enabled for all privileged users", "section": "IAM", "severity": "critical", "status": "passed", "resource_type": "azure::aad::user", "resource_id": "*", "evidence": "Conditional Access policy enforces MFA for all Global Admins.", "remediation": ""},
        {"control_id": "1.3",  "control_name": "Ensure guest users are reviewed on a monthly basis", "section": "IAM", "severity": "medium", "status": "failed", "resource_type": "azure::aad::guestuser", "resource_id": "*", "evidence": "12 guest accounts not reviewed in 90+ days.", "remediation": "Implement Azure AD Access Reviews for guest accounts quarterly."},
        {"control_id": "2.1",  "control_name": "Ensure that Azure Defender is set to On for Servers",  "section": "Defender", "severity": "high", "status": "passed", "resource_type": "azure::security::defenderplan", "resource_id": "Servers", "evidence": "Microsoft Defender for Servers P2 enabled.", "remediation": ""},
        {"control_id": "3.1",  "control_name": "Ensure that storage account access keys are periodically regenerated", "section": "Storage", "severity": "medium", "status": "failed", "resource_type": "azure::storage::account", "resource_id": "aldecistorageprod", "evidence": "Keys not rotated in 180+ days.", "remediation": "Enable automatic key rotation in Azure Key Vault."},
        {"control_id": "4.1",  "control_name": "Ensure that Azure SQL server audit is enabled",         "section": "Database", "severity": "high", "status": "passed", "resource_type": "azure::sql::server", "resource_id": "aldeci-sql-prod", "evidence": "Auditing enabled to Storage Account with 90-day retention.", "remediation": ""},
    ]

    for ctrl in az_controls:
        engine.add_control_result(org_id, az_id, ctrl)

    assessments = engine.list_assessments(org_id)
    return {"engine": "CloudComplianceEngine",
            "assessments": len(assessments),
            "aws_controls": len(aws_controls),
            "azure_controls": len(az_controls)}


# ---------------------------------------------------------------------------
# 14. EndpointComplianceEngine
# ---------------------------------------------------------------------------

def seed_endpoint_compliance(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 6 endpoints with CIS benchmark checks."""
    try:
        from core.endpoint_compliance_engine import EndpointComplianceEngine, _db_path_for_org
    except ImportError as exc:
        return {"engine": "EndpointComplianceEngine", "error": str(exc)}

    engine = EndpointComplianceEngine(db_path=_db_path_for_org(org_id))

    endpoints_def = [
        {"hostname": "ws-eng-001.aldeci.io",    "os_type": "windows", "os_version": "Windows 11 Pro 23H2",  "department": "Engineering",  "owner_id": "alice@aldeci.io"},
        {"hostname": "ws-eng-002.aldeci.io",    "os_type": "windows", "os_version": "Windows 11 Pro 23H2",  "department": "Engineering",  "owner_id": "bob@aldeci.io"},
        {"hostname": "srv-build-01.aldeci.io",  "os_type": "linux",   "os_version": "Ubuntu 24.04 LTS",     "department": "DevOps",       "owner_id": "ci-runner@aldeci.io"},
        {"hostname": "srv-db-01.aldeci.io",     "os_type": "linux",   "os_version": "RHEL 9.4",             "department": "Engineering",  "owner_id": "dba@aldeci.io"},
        {"hostname": "mbp-ciso-01.aldeci.io",   "os_type": "macos",   "os_version": "macOS Sequoia 15.3",   "department": "Security",     "owner_id": "ciso@aldeci.io"},
        {"hostname": "ws-hr-007.aldeci.io",     "os_type": "windows", "os_version": "Windows 10 Pro 22H2",  "department": "HR",           "owner_id": "hr-admin@aldeci.io"},
    ]

    endpoint_ids = []
    for ep in endpoints_def:
        result = engine.register_endpoint(org_id, ep)
        endpoint_ids.append(result["id"])

    # Windows CIS checks for ws-eng-001
    win_checks = [
        {"check_id": "CIS.1.1.1",  "check_name": "Enforce password history (24 passwords)",       "benchmark": "cis_windows_l1", "category": "account_policy", "severity": "high",     "status": "passed",   "actual_value": "24",    "expected_value": "24"},
        {"check_id": "CIS.1.1.2",  "check_name": "Maximum password age (60 days)",                 "benchmark": "cis_windows_l1", "category": "account_policy", "severity": "medium",   "status": "passed",   "actual_value": "60",    "expected_value": "60"},
        {"check_id": "CIS.1.1.3",  "check_name": "Minimum password length (14 chars)",             "benchmark": "cis_windows_l1", "category": "account_policy", "severity": "high",     "status": "failed",   "actual_value": "8",     "expected_value": "14",  "remediation": "Set Minimum password length to 14 via Group Policy."},
        {"check_id": "CIS.1.1.5",  "check_name": "Account lockout duration (15 minutes)",          "benchmark": "cis_windows_l1", "category": "account_policy", "severity": "medium",   "status": "passed",   "actual_value": "15",    "expected_value": ">=15"},
        {"check_id": "CIS.2.2.1",  "check_name": "Windows Firewall: Domain profile enabled",       "benchmark": "cis_windows_l1", "category": "firewall",       "severity": "critical", "status": "passed",   "actual_value": "ON",    "expected_value": "ON"},
        {"check_id": "CIS.2.2.2",  "check_name": "Windows Firewall: Public profile enabled",       "benchmark": "cis_windows_l1", "category": "firewall",       "severity": "critical", "status": "passed",   "actual_value": "ON",    "expected_value": "ON"},
        {"check_id": "CIS.18.9.1", "check_name": "BitLocker: Require additional auth at startup",  "benchmark": "cis_windows_l1", "category": "registry",       "severity": "high",     "status": "passed",   "actual_value": "1",     "expected_value": "1"},
        {"check_id": "CIS.18.9.2", "check_name": "BitLocker: Encrypt OS drive",                    "benchmark": "cis_windows_l1", "category": "registry",       "severity": "critical", "status": "passed",   "actual_value": "Encrypted","expected_value": "Encrypted"},
        {"check_id": "CIS.19.7.1", "check_name": "Windows Update: Auto-download and schedule",     "benchmark": "cis_windows_l1", "category": "service",        "severity": "high",     "status": "failed",   "actual_value": "3",     "expected_value": "4",   "remediation": "Set Windows Update policy to auto-install via WSUS."},
        {"check_id": "CIS.18.3.1", "check_name": "WannaCry mitigation: SMBv1 disabled",            "benchmark": "cis_windows_l1", "category": "network",        "severity": "critical", "status": "passed",   "actual_value": "Disabled","expected_value": "Disabled"},
    ]
    for chk in win_checks:
        chk["scanned_at"] = _ts(days_ago=1)
        engine.record_check(org_id, endpoint_ids[0], chk)

    # Linux CIS checks for srv-build-01
    linux_checks = [
        {"check_id": "CIS.1.1.1",  "check_name": "Ensure /tmp is a separate partition",            "benchmark": "cis_ubuntu",     "category": "local_policy",   "severity": "low",      "status": "failed",   "actual_value": "not_separate", "expected_value": "separate_partition", "remediation": "Add /tmp to /etc/fstab as a separate mount."},
        {"check_id": "CIS.3.1.1",  "check_name": "Ensure IPv6 is disabled if not used",            "benchmark": "cis_ubuntu",     "category": "network",        "severity": "low",      "status": "passed",   "actual_value": "disabled", "expected_value": "disabled"},
        {"check_id": "CIS.5.2.1",  "check_name": "Ensure SSH Protocol is set to 2",                "benchmark": "cis_ubuntu",     "category": "network",        "severity": "critical", "status": "passed",   "actual_value": "2",         "expected_value": "2"},
        {"check_id": "CIS.5.2.4",  "check_name": "Ensure SSH X11 forwarding is disabled",          "benchmark": "cis_ubuntu",     "category": "network",        "severity": "medium",   "status": "passed",   "actual_value": "no",        "expected_value": "no"},
        {"check_id": "CIS.5.3.1",  "check_name": "Ensure password hashing algorithm is SHA-512",   "benchmark": "cis_ubuntu",     "category": "account_policy", "severity": "high",     "status": "passed",   "actual_value": "SHA-512",   "expected_value": "SHA-512"},
        {"check_id": "CIS.6.2.1",  "check_name": "Ensure password fields are not empty",            "benchmark": "cis_ubuntu",     "category": "account_policy", "severity": "critical", "status": "passed",   "actual_value": "none_empty","expected_value": "none_empty"},
        {"check_id": "CIS.4.1.2",  "check_name": "Ensure auditd service is enabled",               "benchmark": "cis_ubuntu",     "category": "event_log",      "severity": "high",     "status": "passed",   "actual_value": "enabled",   "expected_value": "enabled"},
        {"check_id": "CIS.1.3.1",  "check_name": "Ensure AIDE is installed",                        "benchmark": "cis_ubuntu",     "category": "service",        "severity": "medium",   "status": "failed",   "actual_value": "not_installed", "expected_value": "installed", "remediation": "apt install aide && aideinit"},
    ]
    for chk in linux_checks:
        chk["scanned_at"] = _ts(days_ago=1)
        engine.record_check(org_id, endpoint_ids[2], chk)

    endpoints = engine.list_endpoints(org_id)
    return {"engine": "EndpointComplianceEngine",
            "endpoints": len(endpoints),
            "win_checks": len(win_checks),
            "linux_checks": len(linux_checks)}


# ---------------------------------------------------------------------------
# 15. APISecurityEngine (api_security_mgmt_engine)
# ---------------------------------------------------------------------------

def seed_api_security_mgmt(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed API endpoints, keys, abuse events, and scan jobs."""
    try:
        from core.api_security_mgmt_engine import APISecurityEngine
    except ImportError as exc:
        return {"engine": "APISecurityEngine", "error": str(exc)}

    engine = APISecurityEngine()

    api_endpoints = [
        {"endpoint_path": "/api/v1/vulnerabilities",    "http_method": "GET",    "service_name": "vuln-service",     "authentication_required": True,  "rate_limit_per_minute": 120, "is_public": False, "sensitivity_level": "sensitive",  "risk_score": 4.2},
        {"endpoint_path": "/api/v1/vulnerabilities",    "http_method": "POST",   "service_name": "vuln-service",     "authentication_required": True,  "rate_limit_per_minute": 60,  "is_public": False, "sensitivity_level": "sensitive",  "risk_score": 5.8},
        {"endpoint_path": "/api/v1/assets",             "http_method": "GET",    "service_name": "asset-service",    "authentication_required": True,  "rate_limit_per_minute": 200, "is_public": False, "sensitivity_level": "internal",   "risk_score": 3.1},
        {"endpoint_path": "/api/v1/incidents",          "http_method": "POST",   "service_name": "ir-service",       "authentication_required": True,  "rate_limit_per_minute": 30,  "is_public": False, "sensitivity_level": "critical",   "risk_score": 7.5},
        {"endpoint_path": "/api/v1/threat-intel",       "http_method": "GET",    "service_name": "tip-service",      "authentication_required": True,  "rate_limit_per_minute": 100, "is_public": False, "sensitivity_level": "sensitive",  "risk_score": 5.2},
        {"endpoint_path": "/api/v1/reports/export",     "http_method": "POST",   "service_name": "reporting-service","authentication_required": True,  "rate_limit_per_minute": 10,  "is_public": False, "sensitivity_level": "critical",   "risk_score": 8.1},
        {"endpoint_path": "/api/v1/health",             "http_method": "GET",    "service_name": "gateway",          "authentication_required": False, "rate_limit_per_minute": 600, "is_public": True,  "sensitivity_level": "public",     "risk_score": 0.5},
        {"endpoint_path": "/api/v1/auth/token",         "http_method": "POST",   "service_name": "auth-service",     "authentication_required": False, "rate_limit_per_minute": 30,  "is_public": True,  "sensitivity_level": "critical",   "risk_score": 9.2},
    ]

    ep_ids = []
    for ep in api_endpoints:
        result = engine.register_endpoint(org_id, ep)
        ep_ids.append(result["id"])

    # API keys
    key_defs = [
        {"key_name": "SIEM Integration — Splunk Cloud",   "owner_id": "siem-team@aldeci.io",   "scopes": ["read:vulns", "read:incidents", "read:assets"], "rate_limit_per_hour": 5000},
        {"key_name": "Vulnerability Scanner — Tenable",   "owner_id": "vuln-scanner@aldeci.io","scopes": ["read:assets", "write:vulns"],                   "rate_limit_per_hour": 2000},
        {"key_name": "GRC Platform — ServiceNow",         "owner_id": "grc-admin@aldeci.io",   "scopes": ["read:compliance", "write:risks"],               "rate_limit_per_hour": 1000},
        {"key_name": "CI/CD Pipeline — GitHub Actions",   "owner_id": "devops@aldeci.io",      "scopes": ["read:sbom", "write:scan_results"],              "rate_limit_per_hour": 500},
    ]
    for kd in key_defs:
        engine.create_api_key(org_id, kd)

    # Abuse events
    abuse_events = [
        {"event_type": "rate_limit_breach",           "endpoint_id": ep_ids[7], "source_ip": "45.139.122.174", "severity": "high",   "request_payload_preview": "POST /api/v1/auth/token — 847 requests in 60s from single IP", "detected_at": _ts(days_ago=3)},
        {"event_type": "injection_attempt",           "endpoint_id": ep_ids[0], "source_ip": "91.243.44.148",  "severity": "critical","request_payload_preview": "GET /api/v1/vulnerabilities?filter=1 OR 1=1--", "detected_at": _ts(days_ago=5)},
        {"event_type": "bola_attempt",                "endpoint_id": ep_ids[2], "source_ip": "185.220.101.55", "severity": "high",   "request_payload_preview": "GET /api/v1/assets/org_uuid_999 — cross-tenant traversal attempt", "detected_at": _ts(days_ago=8)},
        {"event_type": "sensitive_data_exposure",     "endpoint_id": ep_ids[5], "source_ip": "203.0.113.7",    "severity": "critical","request_payload_preview": "POST /api/v1/reports/export — response contained 4200 PII records", "detected_at": _ts(days_ago=12)},
        {"event_type": "auth_bypass",                 "endpoint_id": ep_ids[7], "source_ip": "194.61.55.219",  "severity": "critical","request_payload_preview": "JWT alg:none attack attempt on /api/v1/auth/token", "detected_at": _ts(days_ago=15)},
    ]
    for ev in abuse_events:
        engine.record_abuse_event(org_id, ev)

    # OWASP API Top 10 scan
    engine.create_scan(org_id, {
        "scan_type": "owasp_api_top10",
        "target_service": "aldeci-gateway",
    })

    endpoints_list = engine.list_endpoints(org_id)
    return {"engine": "APISecurityEngine",
            "endpoints": len(endpoints_list),
            "api_keys": len(key_defs),
            "abuse_events": len(abuse_events)}


# ---------------------------------------------------------------------------
# 16. VulnIntelligenceEngine
# ---------------------------------------------------------------------------

def seed_vuln_intelligence(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed 10 high-profile CVEs with EPSS, KEV data, and subscriptions."""
    try:
        from core.vuln_intelligence_engine import VulnIntelligenceEngine
    except ImportError as exc:
        return {"engine": "VulnIntelligenceEngine", "error": str(exc)}

    engine = VulnIntelligenceEngine()

    cves = [
        {
            "cve_id": "CVE-2024-3400",
            "title": "Palo Alto PAN-OS GlobalProtect OS Command Injection",
            "description": "OS command injection in GlobalProtect feature allows unauthenticated RCE. Exploited by UTA0218 (Volt Typhoon). CVSS 10.0.",
            "cvss_score": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "epss_score": 0.97, "kev_listed": True, "kev_added_date": "2024-04-12",
            "severity": "critical",
            "affected_products": ["Palo Alto PAN-OS 10.2", "Palo Alto PAN-OS 11.0", "Palo Alto PAN-OS 11.1"],
            "exploit_available": True, "exploit_type": "in_the_wild",
            "patch_available": True, "patch_url": "https://security.paloaltonetworks.com/CVE-2024-3400",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3400"],
            "threat_actors_using": ["UTA0218", "Volt Typhoon"],
            "affected_org_assets": ["vpn-gw-01.aldeci.io", "vpn-gw-02.aldeci.io"],
            "status": "patched",
        },
        {
            "cve_id": "CVE-2024-6387",
            "title": "OpenSSH regreSSHion — Remote Unauthenticated RCE",
            "description": "Signal handler race condition in OpenSSH sshd allows unauthenticated RCE as root on glibc-based Linux systems. Affects OpenSSH < 4.4p1 and 8.5p1 to 9.8p1.",
            "cvss_score": 8.1, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.82, "kev_listed": True, "kev_added_date": "2024-07-01",
            "severity": "critical",
            "affected_products": ["OpenSSH < 4.4p1", "OpenSSH 8.5p1 - 9.8p1"],
            "exploit_available": True, "exploit_type": "poc",
            "patch_available": True, "patch_url": "https://www.openssh.com/txt/release-9.8",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387", "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt"],
            "threat_actors_using": [],
            "affected_org_assets": ["srv-build-01.aldeci.io", "srv-db-01.aldeci.io", "srv-api-03.aldeci.io"],
            "status": "patched",
        },
        {
            "cve_id": "CVE-2023-44487",
            "title": "HTTP/2 Rapid Reset Attack — DDoS Amplification",
            "description": "The HTTP/2 protocol allows a denial of service attack (server resource consumption) because request cancellation can reset streams at a very high rate.",
            "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "epss_score": 0.91, "kev_listed": True, "kev_added_date": "2023-10-10",
            "severity": "high",
            "affected_products": ["nginx < 1.25.3", "Apache httpd < 2.4.58", "Golang < 1.21.3"],
            "exploit_available": True, "exploit_type": "in_the_wild",
            "patch_available": True, "patch_url": "https://nginx.org/en/CHANGES-1.25",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
            "threat_actors_using": ["Various DDoS actors"],
            "affected_org_assets": ["nginx-prod-01.aldeci.io", "nginx-prod-02.aldeci.io"],
            "status": "mitigated",
        },
        {
            "cve_id": "CVE-2024-49138",
            "title": "Windows CLFS Driver — Privilege Escalation (KEV)",
            "description": "Windows Common Log File System Driver heap-based buffer overflow allows local privilege escalation to SYSTEM. Actively exploited by ransomware groups.",
            "cvss_score": 7.8, "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.78, "kev_listed": True, "kev_added_date": "2024-12-10",
            "severity": "high",
            "affected_products": ["Windows 10", "Windows 11", "Windows Server 2016", "Windows Server 2019", "Windows Server 2022"],
            "exploit_available": True, "exploit_type": "in_the_wild",
            "patch_available": True, "patch_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49138",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-49138"],
            "threat_actors_using": ["BlackCat/ALPHV", "Cl0p"],
            "affected_org_assets": ["ws-eng-001.aldeci.io", "ws-eng-002.aldeci.io", "ws-hr-007.aldeci.io"],
            "status": "patched",
        },
        {
            "cve_id": "CVE-2025-0282",
            "title": "Ivanti Connect Secure — Pre-Auth Stack Overflow RCE",
            "description": "A stack-based buffer overflow in Ivanti Connect Secure allows unauthenticated RCE. Exploited by UNC5337 (China-nexus) since December 2024.",
            "cvss_score": 9.0, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "epss_score": 0.95, "kev_listed": True, "kev_added_date": "2025-01-08",
            "severity": "critical",
            "affected_products": ["Ivanti Connect Secure < 22.7R2.5", "Ivanti Policy Secure < 22.7R1.2"],
            "exploit_available": True, "exploit_type": "in_the_wild",
            "patch_available": True, "patch_url": "https://forums.ivanti.com/s/article/Security-Advisory-January-2025",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-0282"],
            "threat_actors_using": ["UNC5337"],
            "affected_org_assets": [],
            "status": "new",
        },
        {
            "cve_id": "CVE-2024-55956",
            "title": "Cleo Harmony/VLTrader — Unauthenticated RCE (CLOP)",
            "description": "Unauthenticated Java deserialization RCE in Cleo Harmony and VLTrader file transfer products. Actively exploited by CLOP ransomware group.",
            "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.93, "kev_listed": True, "kev_added_date": "2024-12-13",
            "severity": "critical",
            "affected_products": ["Cleo Harmony < 5.8.0.24", "Cleo VLTrader < 5.8.0.24", "Cleo LexiCom < 5.8.0.24"],
            "exploit_available": True, "exploit_type": "weaponized",
            "patch_available": True, "patch_url": "https://www.cleo.com/security-bulletin-dec-2024",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-55956"],
            "threat_actors_using": ["CLOP"],
            "affected_org_assets": [],
            "status": "analyzed",
        },
        {
            "cve_id": "CVE-2024-21413",
            "title": "Microsoft Outlook — Moniker Link RCE (MFA Bypass)",
            "description": "Improper input validation in Microsoft Outlook allows an attacker to send a crafted URL that bypasses the Protected View Office security feature.",
            "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.72, "kev_listed": False,
            "severity": "critical",
            "affected_products": ["Microsoft Office 2016", "Microsoft Office LTSC 2021", "Microsoft 365 Apps"],
            "exploit_available": True, "exploit_type": "poc",
            "patch_available": True, "patch_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-21413"],
            "threat_actors_using": [],
            "affected_org_assets": ["outlook-clients"],
            "status": "patched",
        },
        {
            "cve_id": "CVE-2024-38021",
            "title": "Microsoft Outlook — Zero-Click RCE (No Preview Required)",
            "description": "Remote code execution vulnerability in Microsoft Outlook that can be triggered without user interaction — no preview needed.",
            "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.68, "kev_listed": False,
            "severity": "critical",
            "affected_products": ["Microsoft 365 Apps for Enterprise", "Microsoft Office 2019"],
            "exploit_available": False, "exploit_type": None,
            "patch_available": True, "patch_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38021",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-38021"],
            "threat_actors_using": [],
            "affected_org_assets": [],
            "status": "patched",
        },
    ]

    for cve in cves:
        engine.add_cve(org_id, cve)

    # Add subscriptions for vendor tracking
    subs = [
        {"subscription_type": "vendor", "value": "Microsoft",      "notify_severity": "high",     "active": True},
        {"subscription_type": "vendor", "value": "Palo Alto Networks", "notify_severity": "critical","active": True},
        {"subscription_type": "vendor", "value": "Ivanti",         "notify_severity": "critical", "active": True},
        {"subscription_type": "product","value": "OpenSSH",        "notify_severity": "high",     "active": True},
        {"subscription_type": "product","value": "nginx",          "notify_severity": "high",     "active": True},
    ]
    for sub in subs:
        try:
            engine.add_subscription(org_id, sub)
        except Exception:
            pass  # subscription may already exist

    cve_list = engine.list_cves(org_id)
    return {"engine": "VulnIntelligenceEngine",
            "cves_seeded": len(cve_list),
            "kev_count": sum(1 for c in cves if c.get("kev_listed")),
            "critical_count": sum(1 for c in cves if c["severity"] == "critical")}


# ---------------------------------------------------------------------------
# 17. ThreatIntelPlatformEngine
# ---------------------------------------------------------------------------

def seed_threat_intel_platform(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed TIP with intel sources, indicators, and a flash report."""
    try:
        from core.threat_intel_platform_engine import ThreatIntelPlatformEngine
    except ImportError as exc:
        return {"engine": "ThreatIntelPlatformEngine", "error": str(exc)}

    engine = ThreatIntelPlatformEngine()

    sources = [
        {"source_name": "Mandiant Advantage",         "source_type": "commercial", "feed_url": "https://api.intelligence.mandiant.com/v4/",              "reliability_score": 0.97, "update_frequency_hours": 1,   "total_indicators": 2_847_000},
        {"source_name": "Recorded Future",             "source_type": "commercial", "feed_url": "https://api.recordedfuture.com/v2/",                     "reliability_score": 0.95, "update_frequency_hours": 1,   "total_indicators": 1_420_000},
        {"source_name": "CISA AIS (Automated Intel Sharing)", "source_type": "government", "feed_url": "https://api.dhs.gov/ais/",                        "reliability_score": 0.98, "update_frequency_hours": 4,   "total_indicators": 340_000},
        {"source_name": "AlienVault OTX",              "source_type": "osint",      "feed_url": "https://otx.alienvault.com/api/v1/",                     "reliability_score": 0.88, "update_frequency_hours": 6,   "total_indicators": 18_500_000},
        {"source_name": "FS-ISAC (Financial Sector)",  "source_type": "isac",       "feed_url": "https://feeds.fsisac.com/stix/",                         "reliability_score": 0.96, "update_frequency_hours": 12,  "total_indicators": 85_000},
        {"source_name": "abuse.ch Feodo Tracker",      "source_type": "osint",      "feed_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json","reliability_score": 0.94, "update_frequency_hours": 1,   "total_indicators": 420},
        {"source_name": "Internal SIEM Correlation",   "source_type": "internal",   "feed_url": "http://siem.aldeci.io/api/v1/iocs/export",               "reliability_score": 0.99, "update_frequency_hours": 0,   "total_indicators": 1_247},
    ]

    source_ids = {}
    for src in sources:
        result = engine.add_source(org_id, src)
        source_ids[src["source_name"]] = result["id"]

    indicators = [
        # IP indicators (C2 infrastructure)
        {"indicator_type": "ip",          "value": "185.220.101.55",              "severity": "critical", "confidence": 0.97, "threat_category": "c2",        "tags": ["emotet", "botnet", "tor-exit"],       "tlp_level": "amber", "source_id": source_ids.get("AlienVault OTX", "")},
        {"indicator_type": "ip",          "value": "91.243.44.148",               "severity": "critical", "confidence": 0.95, "threat_category": "c2",        "tags": ["icedid", "banking-trojan"],           "tlp_level": "amber", "source_id": source_ids.get("abuse.ch Feodo Tracker", "")},
        {"indicator_type": "ip",          "value": "45.139.122.174",              "severity": "high",     "confidence": 0.88, "threat_category": "scanner",   "tags": ["mass-scanner", "shodan"],             "tlp_level": "green", "source_id": source_ids.get("Internal SIEM Correlation", "")},
        {"indicator_type": "ip",          "value": "194.61.55.219",               "severity": "high",     "confidence": 0.91, "threat_category": "apt",       "tags": ["fin7", "carbanak"],                   "tlp_level": "amber", "source_id": source_ids.get("Recorded Future", "")},
        # Domain indicators
        {"indicator_type": "domain",      "value": "apt41-c2.hk-hosting.com",     "severity": "critical", "confidence": 0.98, "threat_category": "apt",       "tags": ["apt41", "supply-chain", "china-nexus"],"tlp_level": "red",  "source_id": source_ids.get("Mandiant Advantage", "")},
        {"indicator_type": "domain",      "value": "lazarus-job-offer.malware.io", "severity": "critical", "confidence": 0.96, "threat_category": "apt",       "tags": ["lazarus", "dprk", "crypto-theft"],    "tlp_level": "red",  "source_id": source_ids.get("CISA AIS (Automated Intel Sharing)", "")},
        {"indicator_type": "domain",      "value": "malware-c2.badactor.ru",       "severity": "high",     "confidence": 0.89, "threat_category": "malware",   "tags": ["agenttesla", "stealer"],              "tlp_level": "amber", "source_id": source_ids.get("AlienVault OTX", "")},
        # File hashes (malware samples)
        {"indicator_type": "file_hash",   "value": "a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", "severity": "critical", "confidence": 0.99, "threat_category": "ransomware", "tags": ["blackcat", "alphv", "byovd"],         "tlp_level": "amber", "source_id": source_ids.get("Mandiant Advantage", "")},
        {"indicator_type": "file_hash",   "value": "70efdf2ec9b086079795c442636b55fb",  "severity": "high",     "confidence": 0.92, "threat_category": "malware",   "tags": ["agenttesla", "keylogger"],            "tlp_level": "amber", "source_id": source_ids.get("Internal SIEM Correlation", "")},
        # CVE indicators
        {"indicator_type": "cve",         "value": "CVE-2024-3400",               "severity": "critical", "confidence": 1.00, "threat_category": "exploit",   "tags": ["panos", "globalprotect", "rce", "kev"],"tlp_level": "white","source_id": source_ids.get("CISA AIS (Automated Intel Sharing)", "")},
        {"indicator_type": "cve",         "value": "CVE-2024-6387",               "severity": "critical", "confidence": 1.00, "threat_category": "exploit",   "tags": ["openssh", "regresshion", "rce", "kev"],"tlp_level": "white","source_id": source_ids.get("CISA AIS (Automated Intel Sharing)", "")},
        # URL
        {"indicator_type": "url",         "value": "hxxp://evil-cdn.biz/payload.exe", "severity": "high", "confidence": 0.87, "threat_category": "malware",   "tags": ["raccoon-stealer", "dropper-url"],     "tlp_level": "amber", "source_id": source_ids.get("AlienVault OTX", "")},
    ]

    for ind in indicators:
        try:
            engine.add_indicator(org_id, ind)
        except Exception:
            pass

    # Flash intel report
    engine.create_report(org_id, {
        "report_name": "FLASH: APT41 Supply Chain Campaign — SaaS Vendor Targeting",
        "report_type": "flash",
        "classification": "confidential",
        "tlp_level": "amber",
        "summary": "APT41 (China-nexus) is actively targeting SaaS vendors via CI/CD pipeline compromise. DLL sideloading TTPs observed. ALDECI supply chain exposure assessed as LOW due to GitHub Actions OIDC hardening.",
        "iocs": ["apt41-c2.hk-hosting.com", "update-srv.software-cdn.net"],
        "mitre_ttps": ["T1195.002", "T1574.002", "T1071.001"],
    })

    indicator_list = engine.search_indicators(org_id, query="", limit=500)
    source_list = engine.list_sources(org_id)
    return {"engine": "ThreatIntelPlatformEngine",
            "sources": len(source_list), "indicators": len(indicator_list)}


# ---------------------------------------------------------------------------
# 18. AttackSurfaceEngine
# ---------------------------------------------------------------------------

def seed_attack_surface(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed attack surface assets and exposure findings."""
    try:
        from core.attack_surface_engine import AttackSurfaceEngine
    except ImportError as exc:
        return {"engine": "AttackSurfaceEngine", "error": str(exc)}

    engine = AttackSurfaceEngine()

    assets = [
        {"asset_type": "domain",       "value": "aldeci.io",              "risk_score": 2.1, "tags": ["primary-domain", "prod"], "notes": "Primary production domain"},
        {"asset_type": "subdomain",    "value": "api.aldeci.io",          "risk_score": 5.4, "tags": ["api-gateway", "public"], "notes": "Public REST API gateway"},
        {"asset_type": "subdomain",    "value": "app.aldeci.io",          "risk_score": 4.2, "tags": ["frontend", "public"],    "notes": "Customer-facing web application"},
        {"asset_type": "subdomain",    "value": "admin.aldeci.io",        "risk_score": 7.8, "tags": ["admin", "internal"],     "notes": "Admin portal — should not be internet-exposed"},
        {"asset_type": "subdomain",    "value": "staging.aldeci.io",      "risk_score": 6.1, "tags": ["staging", "dev"],        "notes": "Staging environment — TLS cert expired"},
        {"asset_type": "ip",           "value": "203.0.113.10",           "risk_score": 3.5, "tags": ["prod", "load-balancer"], "notes": "Primary load balancer IP"},
        {"asset_type": "ip",           "value": "203.0.113.28",           "risk_score": 8.2, "tags": ["legacy", "redis"],       "notes": "Unauthenticated Redis — requires firewall rule"},
        {"asset_type": "certificate",  "value": "CN=aldeci.io,O=ALDECI",  "risk_score": 1.2, "tags": ["ssl", "valid"],          "notes": "Let's Encrypt cert, expires 2026-07-15"},
        {"asset_type": "certificate",  "value": "CN=staging.aldeci.io",   "risk_score": 7.1, "tags": ["ssl", "expired"],        "notes": "Certificate expired 2026-01-10 — renewal overdue"},
        {"asset_type": "api_endpoint", "value": "api.aldeci.io/api/v1/vulnerabilities", "risk_score": 4.8, "tags": ["sensitive", "authenticated"], "notes": "Requires JWT auth"},
        {"asset_type": "cloud_resource","value": "aldeci-data-prod (S3 bucket)", "risk_score": 3.1, "tags": ["aws", "s3", "encrypted"], "notes": "SSE-KMS encrypted. Public access blocked."},
        {"asset_type": "cloud_resource","value": "aldeci-assets-cdn (S3 bucket)", "risk_score": 5.9, "tags": ["aws", "s3", "public"], "notes": "Public bucket — no HTTPS enforcement policy"},
    ]

    asset_ids = {}
    for asset in assets:
        result = engine.add_asset(org_id, asset)
        asset_ids[asset["value"]] = result["id"]

    # Exposures mapped to assets
    exposures = [
        {
            "asset_id": asset_ids.get("203.0.113.28", ""),
            "data": {"exposure_type": "open_port",              "severity": "critical", "title": "Unauthenticated Redis on port 6379 exposed to internet", "description": "Redis 7.0.15 on 203.0.113.28:6379 is internet-accessible with no authentication. Risk: cryptominer deployment, data theft.", "evidence": "nmap: 203.0.113.28 port 6379/tcp open (redis-server 7.0.15 AUTH disabled)", "cvss_score": 9.8, "remediation": "Apply requirepass in redis.conf. Add security group rule to restrict 6379 to VPN CIDR only."},
        },
        {
            "asset_id": asset_ids.get("admin.aldeci.io", ""),
            "data": {"exposure_type": "exposed_admin",          "severity": "high",     "title": "Admin portal exposed on public internet", "description": "admin.aldeci.io is accessible from the internet. Admin portals should be VPN-gated.", "evidence": "curl -I https://admin.aldeci.io returns HTTP 200 from external IP.", "cvss_score": 7.5, "remediation": "Add IP allowlist or WAF rule restricting admin.aldeci.io to corporate VPN CIDR 10.0.0.0/8."},
        },
        {
            "asset_id": asset_ids.get("staging.aldeci.io", ""),
            "data": {"exposure_type": "weak_ssl",               "severity": "high",     "title": "Expired TLS certificate on staging.aldeci.io", "description": "TLS certificate for staging.aldeci.io expired 2026-01-10. Browsers show security warning.", "evidence": "SSL Labs: Certificate expired. Subject: CN=staging.aldeci.io. Expiry: 2026-01-10.", "cvss_score": 5.9, "remediation": "Renew Let's Encrypt certificate via certbot renew. Automate renewal with cron."},
        },
        {
            "asset_id": asset_ids.get("aldeci-assets-cdn (S3 bucket)", ""),
            "data": {"exposure_type": "public_bucket",          "severity": "medium",   "title": "S3 bucket lacks HTTPS-only policy", "description": "aldeci-assets-cdn S3 bucket does not enforce HTTPS. Objects could be accessed over HTTP, enabling MITM attacks.", "evidence": "AWS Config: BucketPolicy missing aws:SecureTransport condition.", "cvss_score": 5.3, "remediation": "Add bucket policy to deny requests where aws:SecureTransport is false."},
        },
        {
            "asset_id": asset_ids.get("api.aldeci.io", ""),
            "data": {"exposure_type": "cors_misconfiguration",  "severity": "medium",   "title": "API gateway returns wildcard CORS header", "description": "Access-Control-Allow-Origin: * returned for authenticated endpoints. Enables cross-origin requests from any domain.", "evidence": "curl -H 'Origin: https://evil.example.com' returns ACAO: *", "cvss_score": 6.1, "remediation": "Restrict CORS to allowlisted origins: aldeci.io, app.aldeci.io. Remove wildcard."},
        },
    ]

    exposures_added = 0
    for exp in exposures:
        if exp["asset_id"]:
            engine.add_exposure(org_id, exp["asset_id"], exp["data"])
            exposures_added += 1

    # Scan job
    engine.create_scan(org_id, {"scan_type": "full", "targets": ["aldeci.io", "203.0.113.0/28"]})

    assets_list = engine.list_assets(org_id)
    return {"engine": "AttackSurfaceEngine",
            "assets": len(assets_list), "exposures": exposures_added}


# ---------------------------------------------------------------------------
# 19. PasswordPolicyEngine
# ---------------------------------------------------------------------------

def seed_password_policy(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed password policies, audit results, violations, and MFA enrollments."""
    try:
        from core.password_policy_engine import PasswordPolicyEngine
    except ImportError as exc:
        return {"engine": "PasswordPolicyEngine", "error": str(exc)}

    engine = PasswordPolicyEngine()

    # Primary NIST 800-63B compliant policy (all users)
    primary = engine.create_policy(org_id, {
        "name": "ALDECI Corporate Password Policy v3 (NIST 800-63B)",
        "min_length": 14,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True,
        "require_digits": True,
        "require_special": True,
        "max_age_days": 365,
        "min_age_days": 1,
        "min_history": 12,
        "history_count": 24,
        "lockout_attempts": 10,
        "lockout_duration_minutes": 30,
        "complexity_score_min": 75,
        "is_active": True,
        "applies_to": ["all_users"],
    })
    primary_id = primary["policy_id"]

    # Privileged accounts policy (stricter)
    engine.create_policy(org_id, {
        "name": "Privileged Account Policy (PAM) — CIS L2",
        "min_length": 20,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True,
        "require_digits": True,
        "require_special": True,
        "max_age_days": 90,
        "min_age_days": 1,
        "min_history": 24,
        "history_count": 24,
        "lockout_attempts": 5,
        "lockout_duration_minutes": 60,
        "complexity_score_min": 90,
        "is_active": True,
        "applies_to": ["admins", "privileged_users", "service_accounts"],
    })

    # Password audit results
    engine.run_audit(org_id, primary_id, {
        "users_audited": 487,
        "total_users_checked": 487,
        "violations_found": 23,
        "compliant": 464,
        "non_compliant": 23,
        "weak_count": 8,
        "expired_count": 11,
        "no_mfa_count": 14,
        "compliance_rate": 95.3,
        "audit_date": _date(days_ago=7),
    })

    # Policy violations
    violations = [
        {"policy_id": primary_id, "user_id": "u-001", "user_email": "contractor-ext01@vendor.com", "violation_type": "weak_password", "severity": "high"},
        {"policy_id": primary_id, "user_id": "u-002", "user_email": "intern-2025@aldeci.io",        "violation_type": "expired_password","severity": "medium"},
        {"policy_id": primary_id, "user_id": "u-003", "user_email": "legacy-svc@aldeci.io",         "violation_type": "no_mfa",          "severity": "high"},
        {"policy_id": primary_id, "user_id": "u-004", "user_email": "temp-user01@aldeci.io",        "violation_type": "reused_password", "severity": "medium"},
        {"policy_id": primary_id, "user_id": "u-005", "user_email": "old-admin@aldeci.io",          "violation_type": "expired_password","severity": "high"},
    ]
    for v in violations:
        try:
            engine.create_violation(org_id, v)
        except Exception:
            pass

    # MFA enrollments (representative sample)
    mfa_users = [
        {"user_id": "u-ciso-01",   "user_email": "ciso@aldeci.io",          "mfa_type": "hardware_key", "enrolled": True},
        {"user_id": "u-eng-001",   "user_email": "alice@aldeci.io",          "mfa_type": "totp",         "enrolled": True},
        {"user_id": "u-eng-002",   "user_email": "bob@aldeci.io",            "mfa_type": "totp",         "enrolled": True},
        {"user_id": "u-grc-001",   "user_email": "grc-lead@aldeci.io",       "mfa_type": "hardware_key", "enrolled": True},
        {"user_id": "u-soc-001",   "user_email": "soc-analyst@aldeci.io",    "mfa_type": "push",         "enrolled": True},
        {"user_id": "u-hr-007",    "user_email": "hr-admin@aldeci.io",        "mfa_type": "sms",          "enrolled": True},
        {"user_id": "u-003",       "user_email": "legacy-svc@aldeci.io",      "mfa_type": "totp",         "enrolled": False},
        {"user_id": "u-ext-01",    "user_email": "contractor-ext01@vendor.com","mfa_type": "email_otp",   "enrolled": True},
    ]
    for mu in mfa_users:
        try:
            engine.register_mfa(org_id, mu)
        except Exception:
            pass

    policies = engine.list_policies(org_id)
    audits = engine.list_audits(org_id)
    mfa = engine.list_mfa_enrollments(org_id)
    return {"engine": "PasswordPolicyEngine",
            "policies": len(policies), "audits": len(audits),
            "mfa_enrollments": len(mfa),
            "violations": len(violations)}


# ---------------------------------------------------------------------------
# 20. SecurityTrainingEngine
# ---------------------------------------------------------------------------

def seed_security_training(org_id: str = ORG_ID, reset: bool = False) -> dict:
    """Seed training courses, enrollments, completions, and a campaign."""
    try:
        from core.security_training_engine import SecurityTrainingEngine
    except ImportError as exc:
        return {"engine": "SecurityTrainingEngine", "error": str(exc)}

    engine = SecurityTrainingEngine()

    courses_def = [
        {"title": "Phishing Awareness & Social Engineering Defense",       "course_type": "phishing_awareness", "difficulty": "beginner",     "format": "interactive", "duration_minutes": 45,  "passing_score": 80, "mandatory": True,  "frequency": "annual",    "cpe_credits": 1.0, "description": "Recognise and report phishing, spear-phishing, and social engineering attacks. Includes simulated phishing test."},
        {"title": "Secure Coding Fundamentals (OWASP Top 10)",             "course_type": "secure_coding",      "difficulty": "intermediate", "format": "interactive", "duration_minutes": 120, "passing_score": 75, "mandatory": True,  "frequency": "annual",    "cpe_credits": 2.0, "description": "OWASP Top 10 2021 — SQL injection, XSS, SSRF, insecure deserialization. Hands-on labs in ALDECI code."},
        {"title": "GDPR & Privacy by Design",                              "course_type": "gdpr",               "difficulty": "beginner",     "format": "video",       "duration_minutes": 60,  "passing_score": 70, "mandatory": True,  "frequency": "annual",    "cpe_credits": 1.0, "description": "GDPR obligations, data subject rights, breach notification. Mandatory for all staff handling personal data."},
        {"title": "Incident Response Procedures & Playbooks",              "course_type": "incident_response",  "difficulty": "intermediate", "format": "interactive", "duration_minutes": 90,  "passing_score": 80, "mandatory": True,  "frequency": "annual",    "cpe_credits": 1.5, "description": "IR lifecycle, ALDECI playbooks, escalation procedures, evidence preservation. Scenario-based exercises."},
        {"title": "Zero Trust Security Architecture",                      "course_type": "zero_trust",         "difficulty": "advanced",     "format": "video",       "duration_minutes": 75,  "passing_score": 75, "mandatory": False, "frequency": "once",      "cpe_credits": 1.5, "description": "Zero Trust principles, identity-centric access, microsegmentation, and ALDECI Zero Trust roadmap."},
        {"title": "AI & LLM Security Risks",                               "course_type": "ai_security",        "difficulty": "intermediate", "format": "video",       "duration_minutes": 60,  "passing_score": 70, "mandatory": False, "frequency": "annual",    "cpe_credits": 1.0, "description": "Prompt injection, training data poisoning, model theft, and ALDECI AI security governance framework."},
        {"title": "Password Security & MFA Best Practices",                "course_type": "password_security",  "difficulty": "beginner",     "format": "interactive", "duration_minutes": 30,  "passing_score": 80, "mandatory": True,  "frequency": "annual",    "cpe_credits": 0.5, "description": "NIST 800-63B compliant password hygiene, passphrase selection, MFA enrollment walkthrough."},
        {"title": "PCI DSS v4.0 Awareness for Engineering",                "course_type": "pci_dss",            "difficulty": "intermediate", "format": "quiz",        "duration_minutes": 50,  "passing_score": 85, "mandatory": True,  "frequency": "annual",    "cpe_credits": 1.0, "description": "PCI DSS v4.0 requirements 6 and 8 for developers handling cardholder data environments."},
    ]

    course_ids = []
    for cd in courses_def:
        result = engine.create_course(org_id, cd)
        course_ids.append(result["course_id"])

    # Enrollments: 3 engineers + HR user + CISO
    users = [
        {"user_id": "u-eng-001", "user_email": "alice@aldeci.io",       "department": "Engineering"},
        {"user_id": "u-eng-002", "user_email": "bob@aldeci.io",         "department": "Engineering"},
        {"user_id": "u-grc-001", "user_email": "grc-lead@aldeci.io",    "department": "GRC"},
        {"user_id": "u-hr-007",  "user_email": "hr-admin@aldeci.io",    "department": "HR"},
        {"user_id": "u-ciso-01", "user_email": "ciso@aldeci.io",        "department": "Security"},
    ]

    enrollment_count = 0
    # Track enrollment_id by (user_id, course_idx) for completions
    enrollment_map: dict = {}
    for user in users:
        # Enroll all users in mandatory courses
        mandatory_idxs = [0, 2, 3, 6]  # phishing, gdpr, IR, password
        for idx in mandatory_idxs:
            rec = engine.enroll_user(
                org_id, course_ids[idx], user["user_id"],
                user_email=user["user_email"], department=user["department"],
                due_date=_date(days_ahead=30),
            )
            enrollment_map[(user["user_id"], idx)] = rec["enrollment_id"]
            enrollment_count += 1

    # Enroll engineers in secure coding + PCI
    for uid, email in [("u-eng-001", "alice@aldeci.io"), ("u-eng-002", "bob@aldeci.io")]:
        for idx in [1, 7]:
            rec = engine.enroll_user(org_id, course_ids[idx], uid, user_email=email, department="Engineering", due_date=_date(days_ahead=45))
            enrollment_map[(uid, idx)] = rec["enrollment_id"]
            enrollment_count += 1

    # Mark some completions using enrollment_id
    completions = [
        ("u-eng-001", 0, 94),   # phishing — passed
        ("u-eng-001", 1, 88),   # secure coding — passed
        ("u-eng-001", 2, 91),   # gdpr — passed
        ("u-eng-002", 0, 76),   # phishing — failed (below passing score 80)
        ("u-grc-001", 2, 98),   # gdpr — passed
        ("u-grc-001", 3, 85),   # IR — passed
        ("u-ciso-01", 3, 100),  # IR — perfect score
    ]
    completions_count = 0
    for user_id, course_idx, score in completions:
        enrollment_id = enrollment_map.get((user_id, course_idx))
        if not enrollment_id:
            continue
        try:
            engine.complete_course(org_id, enrollment_id, score=score)
            completions_count += 1
        except Exception:
            pass

    # Training campaign
    engine.create_campaign(org_id, {
        "campaign_name": "Q2 2026 Security Awareness — All Staff",
        "description": "Mandatory Q2 training covering phishing awareness, password security, and GDPR refresh. Completion deadline: 2026-06-30.",
        "course_ids": [course_ids[0], course_ids[2], course_ids[6]],
        "target_departments": ["Engineering", "HR", "Finance", "Sales", "GRC", "Security"],
        "start_date": _date(days_ago=7),
        "end_date": _date(days_ahead=75),
        "status": "active",
    })

    courses = engine.list_courses(org_id)
    return {"engine": "SecurityTrainingEngine",
            "courses": len(courses), "enrollments": enrollment_count,
            "completions": completions_count}


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
        ("Posture Score Engine",        lambda r: seed_posture(org_id, r)),
        ("Threat Feed Aggregator",      lambda r: seed_threat_feeds(org_id, r)),
        ("Digital Forensics Engine",    lambda r: seed_forensics(org_id, r)),
        ("Security Roadmap Engine",     lambda r: seed_roadmap(org_id, r)),
        ("Data Governance Engine",      lambda r: seed_data_governance(org_id, r)),
        ("Compliance Scanner Engine",   lambda r: seed_compliance(org_id, r)),
        ("Asset Risk Calculator",       lambda r: seed_asset_risk(org_id, r)),
        ("Security Health Engine",      lambda r: seed_health(org_id, r)),
        ("Incident Timeline Engine",    lambda r: seed_timelines(org_id, r)),
        ("Vuln Trend Engine",           lambda r: seed_vuln_trends(org_id, r)),
        # Wave 9+10 engines
        ("Cyber Insurance Engine",      lambda r: seed_cyber_insurance(org_id, r)),
        ("Executive Reporting Engine",  lambda r: seed_executive_reporting(org_id, r)),
        ("Cloud Compliance Engine",     lambda r: seed_cloud_compliance(org_id, r)),
        ("Endpoint Compliance Engine",  lambda r: seed_endpoint_compliance(org_id, r)),
        ("API Security Mgmt Engine",    lambda r: seed_api_security_mgmt(org_id, r)),
        ("Vuln Intelligence Engine",    lambda r: seed_vuln_intelligence(org_id, r)),
        ("Threat Intel Platform Engine",lambda r: seed_threat_intel_platform(org_id, r)),
        ("Attack Surface Engine",       lambda r: seed_attack_surface(org_id, r)),
        ("Password Policy Engine",      lambda r: seed_password_policy(org_id, r)),
        ("Security Training Engine",    lambda r: seed_security_training(org_id, r)),
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
