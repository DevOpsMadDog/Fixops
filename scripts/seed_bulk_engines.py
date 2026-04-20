#!/usr/bin/env python3
"""Bulk seeder for 57 empty engines — covers all Wave 11-41 engines.

Run from repo root:
    PYTHONPATH="suite-core:suite-api" python3 scripts/seed_bulk_engines.py
"""
from __future__ import annotations
import sys, random, uuid
from datetime import datetime, timezone, timedelta, date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suite-core"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suite-api"))

ORG = "default"
random.seed(99)

def _ts(days_ago=0, hours_ago=0):
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)
    return dt.isoformat()

def _date(days_ago=0, days_ahead=0):
    d = date.today() + timedelta(days=days_ahead) - timedelta(days=days_ago)
    return d.isoformat()

def _id(): return str(uuid.uuid4())

SEVERITIES = ["critical", "high", "medium", "low"]
USERS = ["alice@corp.io", "bob@corp.io", "carol@corp.io", "dave@corp.io", "eve@corp.io"]
HOSTS = [f"host-{i:03d}.internal" for i in range(1, 21)]
IPS = [f"10.0.{i}.{j}" for i in range(1,5) for j in range(1,6)]
CLOUD_PROVIDERS = ["aws", "azure", "gcp", "multi_cloud"]


# ---------------------------------------------------------------------------
def seed_access_control():
    from core.access_control_engine import AccessControlEngine, AccessPolicyCreate
    e = AccessControlEngine()
    resource_types = ["file", "api", "database", "network", "application", "service"]
    actions = ["read", "write", "execute", "delete", "admin"]
    count = 0
    for i in range(10):
        try:
            e.create_access_policy(ORG, AccessPolicyCreate(
                name=f"Policy-{i:03d}: {resource_types[i % len(resource_types)]} {actions[i % len(actions)]}",
                resource_type=resource_types[i % len(resource_types)],
                action=actions[i % len(actions)],
                effect="allow",
                conditions={"mfa_required": i % 2 == 0},
            ))
            count += 1
        except Exception as ex:
            print(f"  [WARN] access_control {i}: {ex}")
    return count


def seed_ai_governance():
    from core.ai_governance_engine import AIGovernanceEngine
    e = AIGovernanceEngine()
    models = [
        ("GPT-4 Risk Scorer", "llm", "production"),
        ("Anomaly Detector v2", "classification", "production"),
        ("NLP Phishing Classifier", "nlp", "staging"),
        ("CVSS Predictor", "regression", "production"),
        ("Threat Actor Profiler", "anomaly_detection", "research"),
    ]
    count = 0
    for name, mtype, stage in models:
        try:
            r = e.register_model(ORG, {
                "model_name": name, "model_type": mtype, "version": f"1.{count}.0",
                "deployment_stage": stage, "description": f"AI model: {name}",
                "owner": USERS[count % len(USERS)], "use_case": "security_operations",
                "data_sources": ["siem_events", "threat_feeds"],
            })
            mid = r.get("model_id") or r.get("id")
            if mid:
                e.record_assessment(ORG, {
                    "model_id": mid, "assessment_type": "bias",
                    "findings": f"Bias check passed for {name}", "score": random.randint(70, 98),
                    "assessor": USERS[0], "passed": True,
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] ai_governance {name}: {ex}")
    return count


def seed_alerting():
    from core.alerting_notification_engine import AlertingNotificationEngine
    e = AlertingNotificationEngine()
    channels = ["email", "slack", "pagerduty", "webhook", "webhook"]
    count = 0
    for i in range(8):
        sev = SEVERITIES[i % len(SEVERITIES)]
        try:
            r = e.create_alert_policy(ORG, {
                "name": f"Policy-{i}: {sev.upper()} threshold",
                "severity_threshold": sev,
                "channels": [channels[i % len(channels)]],
                "conditions": {"metric": "alert_count", "operator": ">", "value": i + 1},
                "description": f"Notify on {sev} events via {channels[i % len(channels)]}",
                "enabled": True,
            })
            pid = r.get("policy_id") or r.get("id")
            if pid:
                try:
                    e.acknowledge_alert(ORG, pid, {"acknowledged_by": USERS[0]})
                except Exception:
                    pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] alerting {i}: {ex}")
    return count


def seed_anti_phishing():
    from core.anti_phishing_engine import AntiPhishingEngine
    e = AntiPhishingEngine()
    urls = [
        "hxxps://microsofft-login.net/auth",
        "hxxps://paypa1-secure.com/verify",
        "hxxps://aldeci-login.phish.xyz",
        "hxxps://safe-example.com/page",
        "hxxps://internal-portal.corp.io/login",
    ]
    count = 0
    for url in urls:
        try:
            e.submit_url(ORG, {"url": url, "submitted_by": USERS[0], "source": "user_report"})
            count += 1
        except Exception as ex:
            print(f"  [WARN] anti_phishing url: {ex}")
    sim_types = ["credential_harvest", "malware_link", "attachment", "sms", "voice"]
    for i in range(5):
        try:
            e.record_simulation(ORG, {
                "campaign_name": f"Phish-Sim-Q{i+1}-2025",
                "simulation_type": sim_types[i % len(sim_types)],
                "sent_count": random.randint(50, 200),
                "click_count": random.randint(5, 30),
                "report_count": random.randint(10, 40),
                "conducted_by": USERS[i % len(USERS)],
                "conducted_at": _ts(days_ago=30 * i),
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] anti_phishing sim {i}: {ex}")
    return count


def seed_api_abuse():
    from core.api_abuse_detection_engine import APIAbuseDetectionEngine
    e = APIAbuseDetectionEngine()
    endpoints = ["/api/v1/auth/login", "/api/v1/users", "/api/v1/payments", "/api/v1/export"]
    abuse_types = ["credential_stuffing", "scraping", "rate_limit_abuse", "bola", "bot_traffic"]
    rule_types = ["rate_limit", "ip_block", "pattern_match", "anomaly", "geo_block", "user_agent"]
    count = 0
    for i, ep in enumerate(endpoints):
        try:
            r = e.register_endpoint(ORG, {
                "path": ep, "method": "POST" if "auth" in ep or "pay" in ep else "GET",
                "service": "api-gateway", "criticality": SEVERITIES[i % 4],
            })
            eid = r.get("endpoint_id") or r.get("id")
            if eid:
                e.record_incident(ORG, {
                    "endpoint_id": eid, "abuse_type": abuse_types[i % len(abuse_types)],
                    "source_ip": IPS[i % len(IPS)], "request_count": random.randint(100, 5000),
                    "severity": SEVERITIES[i % 4], "description": f"Abuse detected on {ep}",
                })
                e.create_rule(ORG, {
                    "endpoint_id": eid, "rule_name": f"Block {abuse_types[i % len(abuse_types)]}",
                    "rule_type": rule_types[i % len(rule_types)],
                    "condition": {"requests_per_minute": 100}, "action": "block",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] api_abuse {ep}: {ex}")
    return count


def seed_api_discovery():
    from core.api_discovery_engine import APIDiscoveryEngine
    e = APIDiscoveryEngine()
    count = 0
    services = ["auth-service", "payment-service", "user-service", "notification-service"]
    for i, svc in enumerate(services):
        try:
            r = e.register_endpoint(ORG, {
                "endpoint_path": f"/api/v1/{svc.split('-')[0]}/resource-{i}",
                "http_method": ["GET","POST","PUT","DELETE"][i % 4],
                "service_name": svc, "status": "active",
                "documented": i % 3 != 0, "authenticated": True,
            })
            eid = r.get("endpoint_id") or r.get("id")
            if eid:
                e.create_scan(ORG, {"service_name": svc, "scope": "full", "initiated_by": USERS[0]})
                count += 1
        except Exception as ex:
            print(f"  [WARN] api_discovery {svc}: {ex}")
    return count


def seed_api_gateway_security():
    from core.api_gateway_security_engine import APIGatewaySecurityEngine
    e = APIGatewaySecurityEngine()
    count = 0
    gateways = [
        ("Main API Gateway", "kong", "prod"),
        ("Internal Gateway", "nginx", "staging"),
        ("Partner Gateway", "aws_api_gw", "dev"),
    ]
    for name, vendor, env in gateways:
        try:
            r = e.register_gateway(ORG, {
                "name": name, "gateway_type": vendor, "environment": env,
                "base_url": f"https://{name.lower().replace(' ','-')}.corp.io",
                "endpoints_count": random.randint(20, 100), "version": "3.0",
            })
            gid = r.get("gateway_id") or r.get("id")
            if gid:
                e.register_api(ORG, {
                    "gateway_id": gid, "api_name": f"{name} - Auth API",
                    "version": "v2", "auth_type": "oauth2",
                })
                e.record_security_event(ORG, {
                    "gateway_id": gid, "event_type": "injection_attempt",
                    "source_ip": IPS[count % len(IPS)], "severity": "high",
                    "details": "SQL injection in query param",
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] api_gateway {name}: {ex}")
    return count


def seed_api_inventory():
    from core.api_inventory_engine import APIInventoryEngine
    e = APIInventoryEngine()
    count = 0
    apis = [
        ("Payment API", "rest", "oauth2"),
        ("Internal HR API", "rest", "api_key"),
        ("Partner Webhook", "webhook", "hmac"),
        ("GraphQL Gateway", "graphql", "jwt"),
        ("Legacy SOAP Service", "soap", "basic"),
    ]
    for name, atype, auth in apis:
        try:
            r = e.register_api(ORG, {
                "api_name": name, "api_type": atype, "auth_type": auth,
                "version": "1.0", "owner_team": USERS[count % len(USERS)],
                "base_url": f"https://api.corp.io/{name.lower().replace(' ','-')}",
            })
            aid = r.get("api_id") or r.get("id")
            if aid:
                e.add_endpoint(ORG, aid, {
                    "path": "/health", "method": "GET", "documented": True,
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] api_inventory {name}: {ex}")
    return count


def seed_api_threat_protection():
    from core.api_threat_protection_engine import APIThreatProtectionEngine
    e = APIThreatProtectionEngine()
    count = 0
    threat_types = ["injection", "auth_bypass", "rate_abuse", "data_scraping", "bot_attack"]
    for i, ttype in enumerate(threat_types):
        try:
            r = e.create_protection_rule(ORG, {
                "name": f"Block {ttype.replace('_',' ').title()}",
                "threat_type": ttype, "action": "block",
                "pattern": f"detect_{ttype}", "threshold": 10,
            })
            rid = r.get("rule_id") or r.get("id")
            if rid:
                e.record_threat_event(ORG, {
                    "rule_id": rid, "threat_type": ttype,
                    "source_ip": IPS[i % len(IPS)], "target_endpoint": f"/api/v1/resource-{i}",
                    "action_taken": "blocked", "severity": SEVERITIES[i % 4],
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] api_threat {ttype}: {ex}")
    return count


def seed_app_risk():
    from core.application_risk_engine import ApplicationRiskEngine
    e = ApplicationRiskEngine()
    count = 0
    apps = [
        ("Customer Portal", "web", "prod", "critical"),
        ("Internal HR System", "web", "staging", "high"),
        ("Mobile Banking App", "mobile", "prod", "critical"),
        ("Admin Console", "web", "prod", "critical"),
        ("Data Analytics Platform", "api", "prod", "high"),
    ]
    for name, atype, env, crit in apps:
        try:
            r = e.register_application(ORG, {
                "name": name, "app_type": atype, "environment": env,
                "criticality": crit, "owner_team": USERS[count % len(USERS)],
                "tech_stack": "python,react,postgres",
            })
            aid = r.get("app_id") or r.get("id")
            if aid:
                for sev in ["critical", "high", "medium"]:
                    e.add_finding(ORG, aid, {
                        "title": f"{sev.title()} finding in {name}",
                        "severity": sev, "category": "injection",
                        "description": f"Security finding: {sev} severity",
                        "cwe_id": "CWE-89",
                    })
            count += 1
        except Exception as ex:
            print(f"  [WARN] app_risk {name}: {ex}")
    return count


def seed_asset_groups():
    from core.asset_group_engine import AssetGroupEngine
    e = AssetGroupEngine()
    count = 0
    groups = [
        ("Production Servers", "security-zone"),
        ("Critical Infrastructure", "functional"),
        ("PCI Scope", "compliance"),
        ("Cloud Assets", "cloud"),
        ("DMZ Assets", "network"),
    ]
    for name, gtype in groups:
        try:
            r = e.create_group(ORG, name, gtype,
                description=f"Group: {name}", owner=USERS[0])
            gid = r.get("group_id") or r.get("id")
            if gid:
                for j in range(3):
                    try:
                        e.add_member(ORG, gid, {
                            "asset_id": f"asset-{count*3+j:03d}",
                            "asset_name": f"server-{count*3+j:03d}.internal",
                        })
                    except Exception:
                        pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] asset_groups {name}: {ex}")
    return count


def seed_asset_lifecycle():
    from core.asset_lifecycle_engine import AssetLifecycleEngine
    e = AssetLifecycleEngine()
    count = 0
    assets = [
        ("prod-web-01", "server", "production", "2022-01-15", "2027-01-15"),
        ("fin-db-01", "software", "production", "2021-06-01", "2026-06-01"),
        ("dev-laptop-42", "endpoint", "development", "2023-03-10", "2026-03-10"),
        ("k8s-node-05", "cloud", "production", "2023-09-01", "2025-09-01"),
        ("core-switch-01", "network", "datacenter", "2020-01-01", "2025-01-01"),
    ]
    for name, atype, env, acquired, eol in assets:
        try:
            r = e.register_asset(ORG, {
                "name": name, "asset_type": atype, "environment": env,
                "acquisition_date": acquired, "end_of_life_date": eol,
                "owner": USERS[count % len(USERS)], "criticality": SEVERITIES[count % 4],
                "status": "active",
            })
            aid = r.get("asset_id") or r.get("id")
            if aid:
                try:
                    e.record_maintenance(ORG, aid, {
                        "maintenance_type": "patch", "performed_by": USERS[0],
                        "description": f"Patch applied to {name}", "performed_at": _ts(days_ago=7),
                    })
                except Exception:
                    pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] asset_lifecycle {name}: {ex}")
    return count


def seed_asset_tags():
    from core.asset_tagging_engine import AssetTaggingEngine
    e = AssetTaggingEngine()
    count = 0
    tags = [
        ("environment", "production", "environment"),
        ("pci-scope", "true", "compliance"),
        ("platform-engineering", "owner", "department"),
        ("tier-1", "tier-1", "criticality"),
        ("aws-us-east-1", "us-east-1", "technology"),
    ]
    for tag_key, tag_value, cat in tags:
        try:
            r = e.create_tag(ORG, {
                "tag_key": tag_key, "tag_value": tag_value, "tag_category": cat,
                "description": f"Tag: {tag_key}={tag_value}",
            })
            tid = r.get("tag_id") or r.get("id")
            if tid:
                for j in range(3):
                    try:
                        e.register_asset(ORG, {
                            "asset_id": f"asset-tag-{count*3+j:03d}",
                            "asset_name": f"server-{count*3+j:03d}.corp",
                            "asset_type": "server",
                        })
                        e.assign_tag(ORG, f"asset-tag-{count*3+j:03d}", tid)
                    except Exception:
                        pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] asset_tags {cat}: {ex}")
    return count


def seed_attack_chains():
    from core.attack_chain_engine import AttackChainEngine
    e = AttackChainEngine()
    count = 0
    chains = [
        ("Ransomware Kill Chain", "reconnaissance", ["reconnaissance","weaponization","delivery","exploitation","installation","c2","actions_on_objectives"]),
        ("Supply Chain Attack", "delivery", ["delivery","exploitation","installation","c2"]),
        ("Credential Theft Lateral Movement", "exploitation", ["exploitation","installation","c2","actions_on_objectives"]),
    ]
    for name, phase, phases in chains:
        try:
            r = e.create_chain(ORG, {
                "chain_name": name, "kill_chain_phase": phase,
                "description": f"Attack chain: {name}", "severity": "critical",
            })
            cid = r.get("chain_id") or r.get("id")
            if cid:
                for step_num, phase in enumerate(phases, 1):
                    try:
                        e.add_chain_step(ORG, cid, {
                            "step_number": step_num, "phase": phase,
                            "technique_id": f"T{1000+step_num}",
                            "description": f"Phase {step_num}: {phase.replace('_',' ').title()}",
                        })
                    except Exception:
                        pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] attack_chains {name}: {ex}")
    return count


def seed_awareness_campaigns():
    from core.awareness_campaign_engine import AwarenessCampaignEngine
    e = AwarenessCampaignEngine()
    count = 0
    campaigns = [
        ("Q1 2025 Phishing Awareness", "phishing_sim", 150),
        ("Password Security Training", "training", 200),
        ("Security Awareness Newsletter", "newsletter", 180),
        ("Security Tabletop Exercise", "tabletop", 50),
    ]
    for name, ctype, target in campaigns:
        try:
            r = e.create_campaign(ORG, {
                "title": name, "campaign_type": ctype,
                "target_audience": "all_employees",
                "target_count": target, "start_date": _date(days_ago=60),
                "end_date": _date(days_ago=30),
                "description": f"Security awareness campaign: {name}",
            })
            cid = r.get("campaign_id") or r.get("id")
            if cid:
                for j in range(min(10, target)):
                    try:
                        e.record_participation(ORG, cid, {
                            "user_id": f"user-{j:03d}",
                            "user_email": f"user{j}@corp.io",
                            "completed": j % 3 != 0,
                            "score": random.randint(60, 100) if j % 3 != 0 else None,
                            "completed_at": _ts(days_ago=j) if j % 3 != 0 else None,
                        })
                    except Exception:
                        pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] awareness_campaigns {name}: {ex}")
    return count


def seed_awareness_metrics():
    from core.security_awareness_metrics_engine import SecurityAwarenessMetricsEngine
    e = SecurityAwarenessMetricsEngine()
    count = 0
    depts = ["Engineering", "Finance", "HR", "Sales", "Operations", "Legal"]
    for i, dept in enumerate(depts):
        try:
            for mtype in ["training_completion", "phishing_click_rate", "quiz_score"]:
                e.record_metric(ORG, {
                    "department": dept,
                    "metric_type": mtype,
                    "value": random.uniform(60, 98),
                    "period": _date(days_ago=30),
                    "training_program": "Annual Security Awareness",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] awareness_metrics {dept}: {ex}")
    return count


def seed_behavioral_analytics():
    from core.behavioral_analytics_engine import BehavioralAnalyticsEngine
    e = BehavioralAnalyticsEngine()
    count = 0
    baseline_types = ["login_hours", "data_transfer", "access_volume", "location", "command_frequency"]
    behavior_types = ["login_anomaly", "data_access_spike", "lateral_movement", "geo_anomaly", "off_hours_activity"]
    for i, user in enumerate(USERS):
        try:
            e.establish_baseline(ORG, {
                "entity_id": user, "entity_type": "user",
                "user_id": user,
                "baseline_type": baseline_types[i % len(baseline_types)],
                "baseline_value": 9.0, "std_dev": 2.0, "sample_count": 30,
            })
            e.detect_anomaly(ORG, {
                "entity_id": user, "entity_type": "user",
                "user_id": user,
                "behavior_type": behavior_types[i % len(behavior_types)],
                "deviation_score": round(random.uniform(2.5, 8.0), 2),
                "description": f"Anomalous behavior detected for {user}",
                "severity": SEVERITIES[i % 4],
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] behavioral {user}: {ex}")
    return count


def seed_breach_detection():
    from core.breach_detection_engine import BreachDetectionEngine
    e = BreachDetectionEngine()
    count = 0
    rules = [
        ("Large data exfil to external IP", "behavioral", "critical"),
        ("Credential dump detected", "signature", "critical"),
        ("Lateral movement via SMB", "anomaly", "high"),
        ("Persistence via registry key", "heuristic", "high"),
        ("C2 beacon pattern", "ml_based", "critical"),
    ]
    for name, rtype, sev in rules:
        try:
            r = e.create_detection_rule(ORG, {
                "name": name, "rule_type": rtype, "severity": sev,
                "description": f"Detection rule: {name}",
                "conditions": {"threshold": 1, "window_minutes": 15},
                "enabled": True,
            })
            rid = r.get("rule_id") or r.get("id")
            if rid:
                e.record_detection_event(ORG, {
                    "rule_id": rid, "severity": sev,
                    "entity": HOSTS[count % len(HOSTS)],
                    "source_host": HOSTS[count % len(HOSTS)],
                    "description": f"Rule triggered: {name}",
                    "raw_data": {"source_ip": IPS[count % len(IPS)]},
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] breach_detection {name}: {ex}")
    return count


def seed_browser_security():
    from core.browser_security_engine import BrowserSecurityEngine
    e = BrowserSecurityEngine()
    count = 0
    try:
        r = e.create_policy(ORG, {
            "name": "Corporate Browser Policy",
            "policy_type": "enterprise",
            "settings": {"block_extensions": True, "force_https": True, "safe_browsing": True},
            "description": "Standard corporate browser hardening policy",
            "browsers": ["chrome", "edge"],
        })
        pid = r.get("policy_id") or r.get("id")
        if pid:
            event_types = ["malicious_download", "phishing_attempt", "extension_install", "unsafe_navigation"]
            for i, etype in enumerate(event_types):
                e.record_event(ORG, {
                    "policy_id": pid, "event_type": etype,
                    "user": USERS[i % len(USERS)], "url": f"https://suspicious-site-{i}.biz",
                    "browser": "chrome", "action_taken": "blocked",
                })
                count += 1
        ext_types = ["AdBlock", "LastPass", "Grammarly", "Malicious Extension XYZ"]
        for i, ext in enumerate(ext_types):
            e.register_extension(ORG, {
                "name": ext, "extension_id": f"ext-{i:04d}",
                "browser": "chrome", "approved": i < 3, "risk_level": "high" if i == 3 else "low",
            })
    except Exception as ex:
        print(f"  [WARN] browser_security: {ex}")
    return count


def seed_certificates():
    from core.certificate_lifecycle_engine import CertificateLifecycleEngine
    e = CertificateLifecycleEngine()
    count = 0
    certs = [
        ("*.corp.io", "wildcard", 90),
        ("api.corp.io", "single_domain", 30),
        ("customer-portal.corp.io", "single_domain", 180),
        ("internal-ca.corp.io", "ca", 365),
        ("expired-old.corp.io", "single_domain", -10),
    ]
    for domain, ctype, days_to_expiry in certs:
        try:
            # compute future expiry as days_ago negative
            future_ts = (datetime.now(timezone.utc) + timedelta(days=days_to_expiry)).isoformat()
            e.register_certificate(ORG, {
                "domain": domain, "cert_type": ctype,
                "issuer": "DigiCert Inc", "serial_number": f"SERIAL-{count:06d}",
                "issued_at": _ts(days_ago=max(0, 365 - days_to_expiry)),
                "expires_at": future_ts,
                "status": "expired" if days_to_expiry < 0 else ("expiring_soon" if days_to_expiry < 60 else "valid"),
                "auto_renew": True,
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] certificates {domain}: {ex}")
    return count


def seed_change_management():
    from core.security_change_management_engine import SecurityChangeManagementEngine
    e = SecurityChangeManagementEngine()
    count = 0
    changes = [
        ("Firewall Rule Update", "firewall_rule", "high"),
        ("TLS 1.0 Deprecation", "configuration", "medium"),
        ("MFA Policy Enforcement", "policy", "high"),
        ("WAF Rule Addition", "architecture", "medium"),
        ("Patch Tuesday - Critical Patches", "patch", "critical"),
    ]
    for title, ctype, risk in changes:
        try:
            e.create_change(ORG, {
                "title": title, "change_type": ctype, "risk_level": risk,
                "description": f"Security change: {title}",
                "requested_by": USERS[count % len(USERS)],
                "planned_start": _date(days_ahead=7),
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] change_mgmt {title}: {ex}")
    return count


def seed_cloud_access_security():
    from core.cloud_access_security_engine import CloudAccessSecurityEngine
    e = CloudAccessSecurityEngine()
    count = 0
    apps = [
        ("Salesforce", "saas", "crm"),
        ("Slack", "saas", "communication"),
        ("GitHub", "saas", "development"),
        ("AWS S3", "iaas", "storage"),
        ("Azure DevOps", "paas", "devops"),
    ]
    for name, app_type, category in apps:
        try:
            r = e.register_cloud_app(ORG, {
                "name": name, "app_type": app_type, "category": category,
                "risk_level": SEVERITIES[count % 4], "sanctioned": count % 2 == 0,
                "users_count": random.randint(10, 500),
            })
            aid = r.get("app_id") or r.get("id")
            if aid:
                e.record_access_event(ORG, {
                    "app_id": aid, "user": USERS[count % len(USERS)],
                    "action": "data_download", "data_volume_mb": random.randint(1, 500),
                    "source_ip": IPS[count % len(IPS)],
                })
                e.create_policy(ORG, {
                    "app_id": aid, "policy_name": f"Control {name} access",
                    "action": "monitor", "conditions": {"unsanctioned": True},
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_access {name}: {ex}")
    return count


def seed_cloud_accounts():
    from core.cloud_account_monitoring_engine import CloudAccountMonitoringEngine
    e = CloudAccountMonitoringEngine()
    count = 0
    accounts = [
        ("aws-prod-001", "aws", "production"),
        ("aws-dev-002", "aws", "development"),
        ("azure-corp-001", "azure", "production"),
        ("gcp-data-001", "gcp", "data"),
    ]
    for acc_id, provider, env in accounts:
        try:
            r = e.register_account(ORG, acc_id, f"{provider.upper()} {env.title()} Account", provider, region="us-east-1")
            aid = r.get("id") or r.get("account_id")
            if aid:
                e.record_event(
                    acc_id, ORG,
                    "root_login" if count == 0 else "config_change",
                    SEVERITIES[count % 4],
                    f"resource-{count}",
                    f"Security event in {acc_id}",
                )
            count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_accounts {acc_id}: {ex}")
    return count


def seed_cloud_analytics():
    from core.cloud_security_analytics_engine import CloudSecurityAnalyticsEngine
    e = CloudSecurityAnalyticsEngine()
    count = 0
    event_types = ["api_call", "resource_change", "auth_event", "network_event"]
    for i, etype in enumerate(event_types):
        try:
            e.record_event(ORG, {
                "event_type": etype, "provider": CLOUD_PROVIDERS[i % len(CLOUD_PROVIDERS)],
                "account_id": f"aws-{i:03d}", "resource": f"s3://bucket-{i}",
                "actor": USERS[i % len(USERS)], "severity": SEVERITIES[i % 4],
                "region": "us-east-1",
            })
            e.create_rule(ORG, {
                "rule_name": f"Detect {etype.replace('_',' ').title()}",
                "event_type": etype, "threshold": 5,
                "window_minutes": 60, "severity": SEVERITIES[i % 4],
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_analytics {etype}: {ex}")
    return count


def seed_cloud_native():
    from core.cloud_native_security_engine import CloudNativeSecurityEngine
    e = CloudNativeSecurityEngine()
    count = 0
    providers = ["aws", "azure", "gcp"]
    for i, provider in enumerate(providers):
        try:
            r = e.register_cloud_account(ORG, {
                "account_id": f"{provider}-account-{i:03d}",
                "provider": provider, "environment": "production",
                "name": f"{provider.upper()} Production",
            })
            aid = r.get("account_id") or r.get("id")
            if aid:
                for j in range(3):
                    e.record_misconfiguration(ORG, {
                        "account_id": aid, "resource_type": ["s3","ec2","iam"][j],
                        "resource_id": f"resource-{i*3+j}",
                        "misconfiguration": f"Public access enabled on {['s3','ec2','iam'][j]}",
                        "severity": SEVERITIES[j % 4], "remediation": "Disable public access",
                    })
                    count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_native {provider}: {ex}")
    return count


def seed_cloud_cost_optimization():
    from core.cloud_cost_optimization_engine import CloudCostOptimizationEngine
    e = CloudCostOptimizationEngine()
    count = 0
    tools = [
        ("AWS GuardDuty", "detection", "aws", 500.0),
        ("Azure Defender", "detection", "azure", 800.0),
        ("Prisma Cloud", "cloud", "multi-cloud", 2000.0),
        ("Snyk", "compliance", "saas", 600.0),
    ]
    for name, category, provider, monthly_cost in tools:
        try:
            r = e.register_tool(ORG, name, tool_category=category,
                                cloud_provider=provider, monthly_cost=monthly_cost)
            tid = r.get("tool_id") or r.get("id")
            if tid:
                try:
                    e.add_optimization(tid, ORG,
                        optimization_type="right-sizing",
                        description=f"Optimize {name} usage",
                        estimated_savings=monthly_cost * 0.2,
                    )
                    e.add_roi_assessment(tid, ORG,
                        assessment_period=_date(days_ago=30),
                        incidents_prevented=random.randint(2, 10),
                        avg_incident_cost=50000.0,
                        risk_reduction_pct=0.25,
                    )
                except Exception:
                    pass
                count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_cost {name}: {ex}")
    return count


def seed_cloud_drift():
    from core.cloud_drift_engine import CloudDriftDetectionEngine
    e = CloudDriftDetectionEngine()
    count = 0
    baselines = [
        ("AWS S3 Baseline", "aws", "s3"),
        ("EC2 Security Baseline", "aws", "ec2"),
        ("Azure NSG Baseline", "azure", "network"),
    ]
    for name, provider, resource_type in baselines:
        try:
            r = e.register_baseline(ORG, {
                "name": name, "provider": provider, "resource_type": resource_type,
                "configuration": {"encryption": True, "public_access": False, "logging": True},
                "description": f"IaC baseline: {name}",
            })
            bid = r.get("baseline_id") or r.get("id")
            if bid:
                e.record_drift(ORG, {
                    "baseline_id": bid, "resource_id": f"resource-{count:03d}",
                    "drift_type": "configuration_change",
                    "expected": "public_access=false", "actual": "public_access=true",
                    "severity": "high",
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_drift {name}: {ex}")
    return count


def seed_cloud_governance():
    from core.cloud_governance_engine import CloudGovernanceEngine
    e = CloudGovernanceEngine()
    count = 0
    policies = [
        ("No public S3 buckets", "security", "aws"),
        ("Require MFA for console", "access", "aws"),
        ("No unencrypted storage", "compliance", "azure"),
        ("Approved regions only", "resource", "gcp"),
    ]
    for name, category, provider in policies:
        try:
            r = e.create_governance_policy(ORG, {
                "name": name, "policy_type": category, "provider": provider,
                "resource_type": "storage",
                "severity": SEVERITIES[count % 4],
                "description": f"Cloud governance: {name}", "enabled": True,
            })
            pid = r.get("policy_id") or r.get("id")
            if pid:
                e.record_violation(ORG, {
                    "policy_id": pid, "resource_id": f"s3://bucket-{count}",
                    "account_id": f"aws-{count:03d}", "description": f"Violation: {name}",
                    "severity": SEVERITIES[count % 4],
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_governance {name}: {ex}")
    return count


def seed_cloud_identity():
    from core.cloud_identity_engine import CloudIdentityEngine
    e = CloudIdentityEngine()
    count = 0
    for i, user in enumerate(USERS):
        try:
            r = e.register_identity(ORG, {
                "identity_name": user.split("@")[0],
                "email": user, "cloud_provider": CLOUD_PROVIDERS[i % len(CLOUD_PROVIDERS)],
                "identity_type": "user", "roles": ["developer", "viewer"],
                "mfa_enabled": i % 2 == 0,
            })
            iid = r.get("identity_id") or r.get("id")
            if iid:
                e.record_access_review(ORG, {
                    "identity_id": iid,
                    "reviewer": USERS[0], "decision": "approve" if i < 4 else "revoke",
                    "reason": "Quarterly access review",
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_identity {user}: {ex}")
    return count


def seed_cloud_inventory():
    from core.cloud_resource_inventory_engine import CloudResourceInventoryEngine
    e = CloudResourceInventoryEngine()
    count = 0
    resources = [
        ("i-prod-web-01", "compute", "aws", "running", 75),
        ("s3-data-lake-01", "storage", "aws", "active", 95),
        ("vm-prod-001", "compute", "azure", "running", 80),
        ("gke-cluster-01", "container", "gcp", "running", 70),
        ("rds-mysql-prod", "database", "aws", "available", 85),
    ]
    for rid, rtype, provider, status, score in resources:
        try:
            r = e.register_resource(ORG, {
                "resource_id": rid, "resource_type": rtype, "provider": provider,
                "status": status, "security_score": score,
                "region": "us-east-1", "environment": "production",
                "tags": {"env": "production", "team": "platform"},
            })
            iid = r.get("id") or r.get("resource_id")
            if iid:
                e.record_security_finding(ORG, iid, {
                    "finding_type": "misconfiguration", "severity": SEVERITIES[count % 4],
                    "description": f"Security issue on {rid}",
                    "remediation": "Apply security baseline",
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_inventory {rid}: {ex}")
    return count


def seed_compliance_gaps():
    from core.compliance_gap_engine import ComplianceGapEngine
    e = ComplianceGapEngine()
    count = 0
    assessments = [
        ("SOC2 Gap Analysis Q1 2025", "SOC2"),
        ("PCI DSS v4.0 Assessment", "PCI-DSS"),
        ("ISO 27001 Gap Analysis", "ISO27001"),
    ]
    for name, framework in assessments:
        try:
            r = e.create_assessment(ORG, {
                "assessment_name": name, "framework": framework,
                "scope": "enterprise", "assessor": USERS[0],
                "target_date": _date(days_ahead=90),
            })
            aid = r.get("assessment_id") or r.get("id")
            if aid:
                for j in range(5):
                    e.add_control_gap(ORG, aid, {
                        "control_id": f"{framework.upper()}-{j+1}",
                        "control_name": f"Control {j+1}: Security requirement",
                        "current_state": "partial",
                        "required_state": "full",
                        "gap_description": f"Gap in control {j+1}",
                        "severity": SEVERITIES[j % 4],
                    })
                count += 1
        except Exception as ex:
            print(f"  [WARN] compliance_gaps {name}: {ex}")
    return count


def seed_compliance_mapping():
    from core.compliance_mapping_engine import ComplianceMappingEngine
    e = ComplianceMappingEngine()
    count = 0
    frameworks = ["soc2", "iso27001", "pci_dss", "nist_csf", "hipaa"]
    for fw in frameworks:
        try:
            r = e.add_control(ORG, {
                "framework": fw, "control_id": f"{fw.upper()}-AC-1",
                "control_name": f"{fw.upper()} Access Control",
                "description": f"Access control requirement for {fw.upper()}",
                "category": "access_control",
            })
            cid = r.get("control_id") or r.get("id")
            if cid:
                e.add_mapping(ORG, {
                    "source_control_id": cid,
                    "target_control_id": "PR.AC-1",
                    "source_framework": fw,
                    "target_framework": "nist_csf",
                    "mapping_strength": "strong",
                })
                e.add_evidence(ORG, cid, {
                    "evidence_type": "policy_document",
                    "description": f"Access control policy for {fw.upper()}",
                    "location": f"docs/policies/{fw}_access_control.pdf",
                    "collected_by": USERS[0],
                    "collected_at": _ts(days_ago=7),
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] compliance_mapping {fw}: {ex}")
    return count


def seed_container_posture():
    from core.container_security_posture_engine import ContainerSecurityPostureEngine
    e = ContainerSecurityPostureEngine()
    count = 0
    clusters = [
        ("prod-k8s-us-east", "kubernetes", "production"),
        ("staging-k8s", "kubernetes", "staging"),
        ("openshift-corp", "openshift", "production"),
    ]
    for name, platform, env in clusters:
        try:
            r = e.register_cluster(ORG, {
                "name": name, "platform": platform, "environment": env,
                "version": "1.28", "node_count": random.randint(5, 30),
            })
            cid = r.get("cluster_id") or r.get("id")
            if cid:
                for j, sev in enumerate(["critical", "high", "medium"]):
                    e.record_finding(ORG, {
                        "cluster_id": cid, "severity": sev,
                        "finding_type": ["privilege_escalation","network_policy","misconfiguration"][j],
                        "description": f"{sev.title()} finding in {name}",
                        "remediation": f"Fix {['privilege_escalation','network_policy','misconfiguration'][j]}",
                    })
                count += 1
        except Exception as ex:
            print(f"  [WARN] container_posture {name}: {ex}")
    return count


def seed_container_registry():
    from core.container_registry_security_engine import ContainerRegistrySecurityEngine
    e = ContainerRegistrySecurityEngine()
    count = 0
    registries = [
        ("AWS ECR Production", "ecr", "aws"),
        ("Docker Hub Corporate", "docker", "public"),
        ("Azure Container Registry", "acr", "azure"),
    ]
    for name, rtype, provider in registries:
        try:
            r = e.register_registry(ORG, {
                "name": name, "registry_type": rtype, "provider": provider,
                "url": f"https://registry.{provider}.io",
            })
            rid = r.get("registry_id") or r.get("id")
            if rid:
                e.create_policy(ORG, {
                    "registry_id": rid, "policy_name": f"Block critical vulns in {name}",
                    "action": "block", "severity_threshold": "critical",
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] container_registry {name}: {ex}")
    return count


def seed_container_runtime():
    from core.container_runtime_security_engine import ContainerRuntimeSecurityEngine
    e = ContainerRuntimeSecurityEngine()
    count = 0
    containers = [
        ("nginx-frontend-01", "nginx:latest", "web"),
        ("api-backend-01", "python:3.11", "api"),
        ("db-postgres-01", "postgres:15", "database"),
        ("redis-cache-01", "redis:7", "cache"),
    ]
    for name, image, role in containers:
        try:
            r = e.register_container(ORG, {
                "container_id": f"ctr-{count:04d}",
                "image_name": image, "name": name, "role": role,
                "namespace": "default", "node": HOSTS[count % len(HOSTS)],
                "runtime_status": "running",
            })
            cid = r.get("container_id") or r.get("id")
            if cid:
                e.record_runtime_event(ORG, {
                    "container_id": cid,
                    "event_type": "privilege_escalation" if count == 0 else "unexpected_network_conn",
                    "severity": SEVERITIES[count % 4],
                    "description": f"Runtime event in {name}",
                })
                e.create_policy(ORG, {
                    "policy_name": f"Restrict {role} containers",
                    "policy_type": "block_privileged", "action": "alert",
                    "conditions": {"privileged": False},
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] container_runtime {name}: {ex}")
    return count


def seed_crypto_keys():
    from core.crypto_key_management_engine import CryptoKeyManagementEngine
    e = CryptoKeyManagementEngine()
    count = 0
    keys = [
        ("data-encryption-key-prod", "aes256", "encryption", 365),
        ("signing-key-api", "rsa2048", "signing", 180),
        ("tls-cert-key", "rsa4096", "tls", 90),
        ("hmac-webhook-key", "ed25519", "authentication", 365),
        ("old-key-deprecated", "aes256", "encryption", 30),
    ]
    for name, algo, purpose, expiry_days in keys:
        try:
            r = e.create_key(ORG, {
                "name": name, "key_type": algo,
                "purpose": purpose, "owner": USERS[0],
                "expiry_days": expiry_days,
                "tags": [],
            })
            kid = r.get("key_id") or r.get("id")
            if kid:
                e.record_key_usage(ORG, kid, {
                    "operation": "encrypt", "service": "data-service",
                    "used_at": _ts(hours_ago=1),
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] crypto_keys {name}: {ex}")
    return count


def seed_cyber_threat_intel():
    from core.cyber_threat_intelligence_engine import CyberThreatIntelligenceEngine
    e = CyberThreatIntelligenceEngine()
    count = 0
    reports = [
        ("APT41 Q1 2025 Campaign Analysis", "apt", "critical"),
        ("BlackCat Ransomware Infrastructure Report", "ransomware", "critical"),
        ("Lazarus Group Supply Chain TTPs", "supply_chain", "high"),
        ("FIN7 Financial Sector Targeting", "cybercrime", "high"),
    ]
    for title, cat, sev in reports:
        try:
            r = e.create_intel_report(ORG, {
                "title": title, "category": cat, "severity": sev,
                "tlp": "amber", "confidence": random.randint(75, 95),
                "description": f"Threat intelligence: {title}",
                "source": "internal_analysis",
                "published_at": _ts(days_ago=count * 7),
            })
            rid = r.get("report_id") or r.get("id")
            if rid:
                e.add_ioc_to_report(ORG, rid, {
                    "indicator_type": "ip",
                    "value": IPS[count % len(IPS)],
                    "description": f"C2 server linked to {cat}",
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] cti {title[:30]}: {ex}")
    return count


def seed_dark_web():
    from core.dark_web_monitoring_engine import DarkWebMonitoringEngine
    e = DarkWebMonitoringEngine()
    count = 0
    keywords = [
        ("corp.io", "domain"),
        ("aldeci", "brand"),
        ("finance-portal", "product"),
        ("ceo@corp.io", "email_domain"),
    ]
    for kw, ktype in keywords:
        try:
            e.add_keyword(ORG, {
                "keyword": kw, "keyword_type": ktype,
                "priority": "high", "active": True,
            })
            try:
                e.add_mention(ORG, {
                    "keyword": kw, "source_category": "forum",
                    "url_hash": f"sha256:{uuid.uuid4().hex}",
                    "severity": SEVERITIES[count % 4],
                    "context": f"Mention of {kw} found in dark web forum",
                    "first_seen": _ts(days_ago=14),
                    "mention_type": "brand_mention",
                })
            except Exception:
                pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] dark_web {kw}: {ex}")
    try:
        e.record_credential_exposure(ORG, {
            "email": USERS[0], "source": "paste_site",
            "exposure_type": "credentials",
            "description": "Corporate credentials found on paste site",
            "severity": "critical",
        })
        count += 1
    except Exception as ex:
        print(f"  [WARN] dark_web creds: {ex}")
    return count


def seed_data_discovery():
    from core.data_discovery_engine import DataDiscoveryEngine
    e = DataDiscoveryEngine()
    count = 0
    datastores = [
        ("prod-postgres-main", "database", "pii"),
        ("s3-data-lake", "s3", "financial"),
        ("app-logs-bucket", "data_lake", "ip"),
        ("redis-sessions", "cache", "credentials"),
    ]
    for name, dtype, data_type in datastores:
        try:
            r = e.register_datastore(ORG, {
                "name": name, "datastore_type": dtype,
                "location": f"aws://us-east-1/{name}",
                "owner": USERS[count % len(USERS)],
                "data_classification": "confidential",
            })
            did = r.get("datastore_id") or r.get("id")
            if did:
                e.record_discovery(ORG, did, {
                    "data_type": data_type,
                    "record_count": random.randint(1000, 1000000),
                    "sensitivity": "high", "pii_detected": data_type == "pii",
                })
                e.create_scan_job(ORG, did, {
                    "scan_type": "full",
                    "initiated_by": USERS[0],
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] data_discovery {name}: {ex}")
    return count


def seed_data_exfiltration():
    from core.data_exfiltration_engine import DataExfiltrationEngine
    e = DataExfiltrationEngine()
    count = 0
    incidents = [
        ("Large upload to personal Dropbox", "cloud_upload", "critical", USERS[0]),
        ("USB data transfer on finance laptop", "removable_media", "high", USERS[1]),
        ("Email with PII attachment to external", "email", "high", USERS[2]),
        ("DNS tunneling data transfer", "network_tunnel", "critical", USERS[3]),
    ]
    for title, itype, sev, user in incidents:
        try:
            e.record_incident(ORG, {
                "title": title, "incident_type": itype, "severity": sev,
                "user": user, "data_volume_mb": random.randint(10, 5000),
                "destination": "external", "description": title,
                "detected_at": _ts(days_ago=count * 3),
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] data_exfil {title[:30]}: {ex}")
    try:
        e.create_policy(ORG, {
            "name": "Block large uploads", "policy_type": "prevention",
            "conditions": {"data_volume_mb": 100, "destination": "external"},
            "action": "block", "enabled": True,
        })
    except Exception as ex:
        print(f"  [WARN] data_exfil policy: {ex}")
    return count


def seed_data_lake_security():
    from core.data_lake_security_engine import DataLakeSecurityEngine
    e = DataLakeSecurityEngine()
    count = 0
    stores = [
        ("AWS S3 Data Lake", "s3", "aws"),
        ("Azure Data Lake Storage", "adls", "azure"),
        ("GCS Analytics Bucket", "gcs", "gcp"),
    ]
    for name, stype, provider in stores:
        try:
            r = e.register_data_store(ORG, {
                "name": name, "store_type": stype, "provider": provider,
                "location": f"{provider}://datalake/{name.lower().replace(' ','-')}",
                "data_classification": "confidential",
                "owner": USERS[0],
            })
            sid = r.get("store_id") or r.get("id")
            if sid:
                e.record_access_pattern(ORG, sid, {
                    "user": USERS[count % len(USERS)],
                    "access_type": "bulk_read" if count == 0 else "write",
                    "bytes_accessed": random.randint(1000000, 100000000),
                    "is_anomalous": count == 0,
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] data_lake {name}: {ex}")
    return count


def seed_data_pipeline():
    from core.security_data_pipeline_engine import SecurityDataPipelineEngine
    e = SecurityDataPipelineEngine()
    count = 0
    pipelines = [
        ("SIEM Event Ingestion", "siem", "active"),
        ("Threat Intel Feed Processor", "api", "active"),
        ("Vuln Scanner Results", "file", "active"),
        ("Cloud Trail Ingestion", "cloud", "active"),
    ]
    for name, src_type, status in pipelines:
        try:
            e.register_pipeline(ORG, {
                "name": name, "source_type": src_type, "status": status,
                "description": f"Data pipeline: {name}",
                "owner": USERS[0], "schedule": "*/5 * * * *",
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] data_pipeline {name}: {ex}")
    return count


def seed_data_privacy():
    from core.data_privacy_engine import DataPrivacyEngine, DataAssetCreate, PrivacyRequestCreate
    e = DataPrivacyEngine()
    count = 0
    assets = [
        ("Customer PII Database", "database", "confidential", "pii"),
        ("Employee HR Records", "database", "restricted", "phi"),
        ("Payment Card Data", "database", "confidential", "financial"),
    ]
    for name, atype, classification, data_cat in assets:
        try:
            r = e.register_data_asset(ORG, DataAssetCreate(
                name=name, asset_type=atype, classification=classification,
                data_category=data_cat,
                owner=USERS[0], retention_days=365,
                description=f"Data asset: {name}",
            ))
            count += 1
        except Exception as ex:
            print(f"  [WARN] data_privacy {name}: {ex}")
    for i in range(4):
        try:
            e.record_privacy_request(ORG, PrivacyRequestCreate(
                request_type=["access","deletion","portability","rectification"][i],
                subject_email=f"subject{i}@external.com",
                description=f"GDPR data subject request {i}",
                received_at=_ts(days_ago=i * 5),
            ))
            count += 1
        except Exception as ex:
            print(f"  [WARN] data_privacy request {i}: {ex}")
    return count


def seed_ddos_protection():
    from core.ddos_protection_engine import DDoSProtectionEngine
    e = DDoSProtectionEngine()
    count = 0
    resources = [
        ("Customer Portal", "web", "critical"),
        ("API Gateway", "api", "critical"),
        ("DNS Servers", "dns", "high"),
        ("Load Balancer", "network", "high"),
    ]
    for name, rtype, crit in resources:
        try:
            r = e.register_protected_resource(ORG, {
                "name": name, "resource_type": rtype,
                "ip_or_fqdn": IPS[count % len(IPS)],
                "criticality": crit,
                "protection_tier": "standard",
            })
            rid = r.get("resource_id") or r.get("id")
            if rid:
                e.record_attack_event(ORG, {
                    "resource_id": rid, "attack_type": "volumetric",
                    "peak_gbps": random.uniform(1.0, 50.0),
                    "duration_minutes": random.randint(5, 120),
                    "mitigated": True,
                    "source_countries": ["CN", "RU", "KP"],
                })
                e.create_mitigation_rule(ORG, {
                    "resource_id": rid, "rule_name": f"Rate limit {name}",
                    "action": "rate_limit", "threshold_rps": 10000,
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] ddos {name}: {ex}")
    return count


def seed_deception_analytics():
    from core.deception_analytics_engine import DeceptionAnalyticsEngine
    e = DeceptionAnalyticsEngine()
    count = 0
    try:
        r = e.create_campaign(ORG, {
            "name": "Q1 2025 Honeypot Campaign",
            "description": "Internal honeypot network deployment",
            "target_segments": ["finance", "engineering"],
        })
        cid = r.get("campaign_id") or r.get("id")
    except Exception:
        cid = None
    assets = [
        ("honeypot-finance-01", "honeypot", "finance"),
        ("canary-token-hr-docs", "canary_file", "hr"),
        ("honey-db-creds", "canary_cred", "database"),
    ]
    for name, atype, segment in assets:
        try:
            r = e.register_asset(ORG, {
                "name": name, "asset_type": atype, "segment": segment,
                "campaign_id": cid, "deception_type": "honeypot",
            })
            aid = r.get("asset_id") or r.get("id")
            if aid:
                for j in range(2):
                    e.record_interaction(ORG, {
                        "asset_id": aid, "source_ip": IPS[j % len(IPS)],
                        "interaction_type": "connection_attempt",
                        "attacker_fingerprint": f"fp-{uuid.uuid4().hex[:8]}",
                    })
                count += 1
        except Exception as ex:
            print(f"  [WARN] deception {name}: {ex}")
    return count


def seed_digital_identity():
    from core.digital_identity_engine import DigitalIdentityEngine
    e = DigitalIdentityEngine()
    count = 0
    for i, user in enumerate(USERS):
        try:
            r = e.create_profile(ORG, {
                "user_id": user, "identity_level": ["ial1","ial2","ial3"][i % 3],
                "attributes": {"email": user, "department": ["eng","fin","hr"][i % 3]},
                "status": "active",
            })
            pid = r.get("profile_id") or r.get("id")
            if pid:
                e.record_verification_event(ORG, {
                    "profile_id": pid,
                    "event_type": "identity_verified",
                    "method": ["document","biometric","knowledge"][i % 3],
                    "verified_by": "automated",
                    "verification_level": ["ial1","ial2","ial3"][i % 3],
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] digital_identity {user}: {ex}")
    return count


def seed_digital_twin():
    from core.digital_twin_security_engine import DigitalTwinSecurityEngine
    e = DigitalTwinSecurityEngine()
    count = 0
    twins = [
        ("Production Network Twin", "network", "prod-network"),
        ("Finance App Twin", "application", "finance-portal"),
        ("Cloud Infra Twin", "infrastructure", "aws-us-east"),
    ]
    for name, ttype, source in twins:
        try:
            r = e.create_twin(ORG, {
                "name": name, "twin_type": ttype, "source_id": source,
                "description": f"Digital twin: {name}",
                "configuration": {"nodes": 10, "connections": 25},
            })
            tid = r.get("twin_id") or r.get("id")
            if tid:
                for sev in ["critical", "high"]:
                    e.add_finding(ORG, tid, {
                        "title": f"{sev.title()} risk in {name}",
                        "severity": sev, "finding_type": "vulnerability_scan",
                        "description": f"{sev.title()} risk found in {name} simulation",
                        "recommendation": "Apply network segmentation",
                    })
                count += 1
        except Exception as ex:
            print(f"  [WARN] digital_twin {name}: {ex}")
    return count


def seed_email_filtering():
    from core.email_filtering_engine import EmailFilteringEngine
    e = EmailFilteringEngine()
    count = 0
    rules = [
        ("Block known malware senders", "malware", "critical"),
        ("Quarantine external attachments", "spam", "high"),
        ("Flag phishing attempts", "phishing", "medium"),
        ("Block spoofed domains", "dmarc", "high"),
    ]
    for name, rtype, sev in rules:
        try:
            e.create_filter_rule(ORG, {
                "name": name, "rule_type": rtype, "severity": sev,
                "action": "block" if sev in ["critical","high"] else "quarantine",
                "enabled": True, "description": name,
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] email_filtering {name}: {ex}")
    return count


def seed_endpoint_hunting():
    from core.endpoint_threat_hunting_engine import EndpointThreatHuntingEngine
    e = EndpointThreatHuntingEngine()
    count = 0
    hunts = [
        ("Hunt for Cobalt Strike beacons", "proactive", ["T1071.001","T1055"]),
        ("Lateral movement via PsExec", "reactive", ["T1021.002"]),
        ("Persistence via Scheduled Tasks", "scheduled", ["T1053.005"]),
    ]
    for name, htype, techniques in hunts:
        try:
            r = e.create_hunt(ORG, {
                "name": name, "hunt_type": htype,
                "hypothesis": f"Hypothesis: {name}",
                "techniques": techniques, "assigned_to": USERS[0],
                "priority": "high",
            })
            hid = r.get("hunt_id") or r.get("id")
            if hid:
                e.record_finding(ORG, {
                    "hunt_id": hid, "host": HOSTS[count % len(HOSTS)],
                    "finding_type": "malware",
                    "description": f"Finding in hunt: {name}",
                    "severity": "high",
                })
                e.add_ioc(ORG, {
                    "hunt_id": hid, "ioc_type": "ip",
                    "value": IPS[count % len(IPS)],
                    "description": f"IOC found during {name}",
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] endpoint_hunting {name}: {ex}")
    return count


def seed_evidence_vault():
    from core.evidence_vault_engine import EvidenceVaultEngine
    e = EvidenceVaultEngine()
    count = 0
    collections = [
        ("BlackCat Ransomware Investigation", "incident", "2025-Q1", "forensics-team"),
        ("PCI Audit Evidence Q1 2025", "pci_dss", "2025-Q1", "auditor@corp.io"),
        ("Insider Threat Case 2025-03", "incident", "2025-Q1", "security-team"),
    ]
    for name, framework, audit_period, auditor in collections:
        try:
            r = e.create_collection(ORG, name, framework, audit_period, auditor)
            cid = r.get("collection_id") or r.get("id")
            if cid:
                # add_to_collection(collection_id, evidence_id, org_id)
                for j in range(3):
                    evidence_id = f"evidence-{count*3+j:04d}"
                    try:
                        e.add_to_collection(cid, evidence_id, ORG)
                    except Exception:
                        pass
                count += 1
        except Exception as ex:
            print(f"  [WARN] evidence_vault {name}: {ex}")
    return count


def seed_feed_subscriptions():
    from core.threat_feed_subscription_engine import ThreatFeedSubscriptionEngine
    e = ThreatFeedSubscriptionEngine()
    count = 0
    feeds = [
        ("MISP Community Feed", "community", "https://misp.community/feed"),
        ("URLhaus Malware Domains", "osint", "https://urlhaus-api.abuse.ch/v1/"),
        ("Feodo Tracker C2", "osint", "https://feodotracker.abuse.ch/downloads/ipblocklist.json"),
        ("OpenPhish Feed", "osint", "https://openphish.com/feed.txt"),
    ]
    for name, ftype, url in feeds:
        try:
            r = e.create_subscription(ORG, name, ftype, url, api_key="demo-key-placeholder")
            sid = r.get("subscription_id") or r.get("id")
            if sid:
                try:
                    e.record_ingestion(sid, ORG,
                        iocs_fetched=random.randint(100, 5000),
                        iocs_new=random.randint(50, 2000),
                        iocs_updated=random.randint(10, 500),
                        status="success",
                    )
                except Exception:
                    pass
                count += 1
        except Exception as ex:
            print(f"  [WARN] feed_subs {name}: {ex}")
    return count


def seed_firewall_policy():
    from core.firewall_policy_engine import FirewallPolicyEngine
    e = FirewallPolicyEngine()
    count = 0
    firewalls = [
        ("Core Perimeter Firewall", "palo_alto", "perimeter"),
        ("Internal Segmentation FW", "fortinet", "internal"),
        ("Cloud WAF", "aws_sg", "cloud"),
    ]
    for name, fw_type, role in firewalls:
        try:
            r = e.register_firewall(ORG, {
                "name": name, "fw_type": fw_type, "role": role,
                "management_ip": IPS[count % len(IPS)],
                "description": f"{role} firewall",
            })
            fid = r.get("firewall_id") or r.get("id")
            if fid:
                for j in range(3):
                    e.add_rule(ORG, fid, {
                        "rule_name": f"Rule-{j:03d}",
                        "action": ["allow","deny","drop"][j],
                        "source": "10.0.0.0/8" if j < 2 else "any",
                        "destination": "any",
                        "port": str(443 * (j+1)),
                        "protocol": "tcp",
                        "enabled": True,
                    })
                count += 1
        except Exception as ex:
            print(f"  [WARN] firewall {name}: {ex}")
    return count


def seed_firmware_security():
    from core.firmware_security_engine import FirmwareSecurityEngine
    e = FirmwareSecurityEngine()
    count = 0
    devices = [
        ("Cisco ASA Firewall", "router", "15.1.1"),
        ("Core Network Switch", "switch", "U20"),
        ("IoT Temperature Sensor", "embedded", "2.1.0"),
        ("Industrial PLC Controller", "plc", "3.4.2"),
    ]
    for name, dtype, ver in devices:
        try:
            r = e.register_device(ORG, {
                "name": name, "device_type": dtype,
                "firmware_version": ver, "manufacturer": "Generic Corp",
                "model": f"Model-{count:03d}", "criticality": SEVERITIES[count % 4],
            })
            did = r.get("device_id") or r.get("id")
            if did:
                e.record_vulnerability(ORG, {
                    "device_id": did, "cve_id": f"CVE-2024-{10000+count}",
                    "severity": SEVERITIES[count % 4],
                    "description": f"Firmware vulnerability in {name}",
                    "cvss_score": round(random.uniform(5.0, 9.8), 1),
                })
                e.create_scan(ORG, {
                    "device_id": did, "scan_type": "static",
                    "initiated_by": USERS[0],
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] firmware {name}: {ex}")
    return count


def seed_forensics_readiness():
    from core.forensics_readiness_engine import ForensicsReadinessEngine
    e = ForensicsReadinessEngine()
    count = 0
    sources = [
        ("SIEM Event Logs", "application_logs", "splunk"),
        ("Endpoint Memory Dumps", "endpoint_logs", "velociraptor"),
        ("Network PCAP", "network_pcap", "zeek"),
        ("Cloud Trail Logs", "cloud_trail", "aws"),
    ]
    for name, etype, tool in sources:
        try:
            r = e.register_evidence_source(ORG, {
                "name": name, "evidence_type": etype,
                "collection_tool": tool,
                "retention_days": 365,
                "description": f"Evidence source: {name}",
            })
            eid = r.get("source_id") or r.get("id")
            if eid:
                e.create_collection_plan(ORG, {
                    "name": f"Collection plan: {name}",
                    "incident_type": "ransomware",
                    "priority": "high",
                    "target_sources": [eid],
                    "collection_steps": ["Preserve logs", "Capture memory", "Disk image"],
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] forensics {name}: {ex}")
    return count


def seed_hunting_automation():
    from core.hunting_automation_engine import HuntingAutomationEngine
    e = HuntingAutomationEngine()
    count = 0
    hypotheses = [
        ("Detect Mimikatz credential dumping", "privilege_escalation", "T1003", "high"),
        ("Hunt for Cobalt Strike C2 beacons", "lateral_movement", "T1071.001", "medium"),
        ("Find persistence via startup folder", "persistence", "T1547.001", "high"),
    ]
    for name, htype, technique, confidence in hypotheses:
        try:
            r = e.create_hypothesis(
                ORG, name, htype, technique, confidence,
                data_sources=["siem", "edr"],
                created_by=USERS[0],
            )
            hid = r.get("hypothesis_id") or r.get("id")
            if hid:
                e.add_query(
                    hid, ORG,
                    query_name=f"Query for {name}",
                    query_language="SPL",
                    query_content=f"index=main sourcetype=WinEventLog {technique}",
                    data_source="siem",
                )
                count += 1
        except Exception as ex:
            print(f"  [WARN] hunting_auto {name}: {ex}")
    return count


def seed_identity_risk():
    from core.identity_risk_engine import IdentityRiskEngine
    e = IdentityRiskEngine()
    count = 0
    for i, user in enumerate(USERS):
        try:
            r = e.register_identity(ORG, {
                "user_id": user, "display_name": user.split("@")[0],
                "department": ["Engineering","Finance","HR","Sales","Ops"][i % 5],
                "role": ["developer","admin","analyst","manager","auditor"][i % 5],
                "mfa_enrolled": i % 2 == 0,
            })
            iid = r.get("identity_id") or r.get("id")
            if iid:
                factor_types = ["excess_privileges", "mfa_bypass", "stale_credentials", "after_hours_access", "suspicious_location"]
                e.record_risk_factor(ORG, {
                    "identity_id": iid,
                    "factor_type": factor_types[i % len(factor_types)],
                    "severity": SEVERITIES[i % 4],
                    "description": f"Risk factor for {user}",
                    "score": random.randint(20, 90),
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] identity_risk {user}: {ex}")
    return count


def seed_incident_comms():
    from core.incident_comms_engine import IncidentCommsEngine
    e = IncidentCommsEngine()
    count = 0
    comms = [
        ("INC-001 Initial Notification", "initial_notification", "email"),
        ("INC-001 Status Update — Contained", "status_update", "slack"),
        ("INC-001 Executive Brief", "stakeholder_brief", "email"),
        ("INC-002 Customer Resolution Notice", "resolution", "email"),
    ]
    for title, ctype, channel in comms:
        try:
            r = e.create_comm(ORG, {
                "subject": title, "comm_type": ctype, "channel": channel,
                "incident_id": "INC-001" if "001" in title else "INC-002",
                "body": f"Incident communication: {title}",
                "recipients": [USERS[0], USERS[1]],
                "drafted_by": USERS[0],
            })
            cid = r.get("comm_id") or r.get("id")
            if cid:
                try:
                    e.send_comm(ORG, cid)
                except Exception:
                    pass
                count += 1
        except Exception as ex:
            print(f"  [WARN] incident_comms {title}: {ex}")
    return count


def seed_incident_costs():
    from core.incident_cost_engine import IncidentCostEngine
    e = IncidentCostEngine()
    count = 0
    incidents = [
        ("INC-001", "Ransomware BlackCat", "ransomware"),
        ("INC-002", "Data Breach PCI", "data-breach"),
        ("INC-003", "DDoS Attack Portal", "ddos"),
    ]
    cost_categories = ["forensics", "legal", "recovery", "personnel", "tools"]
    for inc_id, inc_name, inc_type in incidents:
        try:
            for cat in cost_categories[:3]:
                e.record_cost(
                    ORG, inc_id, inc_name, inc_type, cat,
                    round(random.uniform(5000, 100000), 2),
                    currency="USD", estimated=True,
                    description=f"{cat.title()} cost for {inc_id}",
                    recorded_by=USERS[0],
                )
            count += 1
        except Exception as ex:
            print(f"  [WARN] incident_costs {inc_id}: {ex}")
    return count


def seed_ip_reputation():
    from core.ip_reputation_engine import IPReputationEngine
    e = IPReputationEngine()
    count = 0
    bad_ips = [
        ("185.234.219.108", "c2_server", 95, "critical"),
        ("91.243.44.148", "botnet", 90, "critical"),
        ("194.61.55.219", "tor_exit", 75, "high"),
        ("103.75.201.2", "scanner", 60, "medium"),
        ("51.178.61.60", "c2_server", 88, "high"),
    ]
    for ip, category, score, sev in bad_ips:
        try:
            e.submit_reputation(ORG, {
                "ip_address": ip, "category": category,
                "reputation_score": score, "severity": sev,
                "source": "threat_intel_feed",
                "last_seen": _ts(hours_ago=random.randint(1, 72)),
                "confidence": 0.9,
            })
            if score > 85:
                e.add_to_blocklist(ORG, ip, f"High-confidence {category}")
            count += 1
        except Exception as ex:
            print(f"  [WARN] ip_rep {ip}: {ex}")
    return count


def seed_iot_security():
    from core.iot_security_engine import IoTSecurityEngine
    e = IoTSecurityEngine()
    count = 0
    devices = [
        ("Office HVAC Controller", "hvac", "building_automation"),
        ("IP Camera — Lobby", "camera", "physical_security"),
        ("Smart Badge Reader — Main Entrance", "access_control", "physical_security"),
        ("Industrial Sensor Array", "sensor", "ot"),
        ("Network Printer — Finance", "printer", "office"),
    ]
    for name, dtype, category in devices:
        try:
            r = e.register_device(ORG, {
                "name": name, "device_type": dtype, "category": category,
                "ip_address": IPS[count % len(IPS)],
                "firmware_version": f"1.{count}.0",
                "manufacturer": "IoT Corp",
                "criticality": SEVERITIES[count % 4],
            })
            did = r.get("device_id") or r.get("id")
            if did:
                e.record_anomaly(ORG, {
                    "device_id": did, "anomaly_type": "unusual_traffic",
                    "severity": SEVERITIES[count % 4],
                    "description": f"Anomalous traffic from {name}",
                })
                e.create_policy(ORG, {
                    "policy_name": f"Isolate {dtype} devices",
                    "device_type": dtype, "action": "segment",
                    "enabled": True,
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] iot {name}: {ex}")
    return count


def seed_itdr():
    from core.itdr_engine import ITDREngine
    e = ITDREngine()
    count = 0
    threats = [
        (USERS[0], "impossible_travel", "critical"),
        (USERS[1], "privilege_abuse", "critical"),
        (USERS[2], "lateral_movement", "high"),
        (USERS[3], "mfa_bypass", "high"),
        (USERS[4], "credential_stuffing", "medium"),
    ]
    for user, ttype, sev in threats:
        try:
            r = e.detect_threat(ORG, {
                "user_id": user, "threat_type": ttype,
                "severity": sev, "confidence": round(random.uniform(0.7, 0.99), 2),
                "source_ip": IPS[count % len(IPS)],
                "detected_at": _ts(hours_ago=count * 3),
            })
            tid = r.get("threat_id") or r.get("id")
            if tid:
                e.create_response_action(ORG, {
                    "threat_id": tid, "action_type": "disable_account",
                    "description": f"Auto-response to {ttype}",
                    "initiated_by": "automated",
                })
                count += 1
        except Exception as ex:
            print(f"  [WARN] itdr {user}: {ex}")
    return count


def seed_ransomware_protection():
    from core.ransomware_protection_engine import RansomwareProtectionEngine
    e = RansomwareProtectionEngine()
    count = 0
    try:
        detection_names = ["file_encryption","shadow_copy_deletion","network_share_encrypt","backup_deletion","ransom_note"]
        detection_types = ["behavioral", "signature", "heuristic", "endpoint", "network"]
        for i in range(5):
            e.register_detection(
                ORG,
                detection_name=f"Ransomware: {detection_names[i]}",
                detection_type=detection_types[i],
                affected_systems=["prod-srv-01", "finance-srv-02"],
                file_extensions=[".encrypted", ".locked"],
                confidence=0.9 if i < 3 else 0.7,
                severity="critical" if i < 3 else "high",
            )
            count += 1
        backup_systems = ['prod-db','finance-data','hr-records','app-configs']
        backup_types = ["full","incremental","snapshot","full"]
        for i in range(4):
            e.register_backup(
                ORG,
                system_name=f"Backup-{backup_systems[i]}",
                backup_type=backup_types[i],
                backup_location=f"s3://backups/{backup_systems[i]}",
                encrypted=True,
                retention_days=90,
            )
            count += 1
        e.create_playbook(
            ORG,
            playbook_name="Ransomware Incident Response",
            trigger_type="manual",
            steps=[
                "Isolate affected systems",
                "Preserve forensic evidence",
                "Identify patient zero",
                "Restore from clean backups",
                "Post-incident review",
            ],
            estimated_mins=120,
        )
        count += 1
    except Exception as ex:
        print(f"  [WARN] ransomware: {ex}")
    return count


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
SEEDERS = [
    ("access_control",       seed_access_control),
    ("ai_governance",        seed_ai_governance),
    ("alerting",             seed_alerting),
    ("anti_phishing",        seed_anti_phishing),
    ("api_abuse",            seed_api_abuse),
    ("api_discovery",        seed_api_discovery),
    ("api_gateway_security", seed_api_gateway_security),
    ("api_inventory",        seed_api_inventory),
    ("api_threat_protection",seed_api_threat_protection),
    ("app_risk",             seed_app_risk),
    ("asset_groups",         seed_asset_groups),
    ("asset_lifecycle",      seed_asset_lifecycle),
    ("asset_tags",           seed_asset_tags),
    ("attack_chains",        seed_attack_chains),
    ("awareness_campaigns",  seed_awareness_campaigns),
    ("awareness_metrics",    seed_awareness_metrics),
    ("behavioral_analytics", seed_behavioral_analytics),
    ("breach_detection",     seed_breach_detection),
    ("browser_security",     seed_browser_security),
    ("certificates",         seed_certificates),
    ("change_management",    seed_change_management),
    ("cloud_access_security",seed_cloud_access_security),
    ("cloud_accounts",       seed_cloud_accounts),
    ("cloud_analytics",      seed_cloud_analytics),
    ("cloud_native",         seed_cloud_native),
    ("cloud_cost",           seed_cloud_cost_optimization),
    ("cloud_drift",          seed_cloud_drift),
    ("cloud_governance",     seed_cloud_governance),
    ("cloud_identity",       seed_cloud_identity),
    ("cloud_inventory",      seed_cloud_inventory),
    ("compliance_gaps",      seed_compliance_gaps),
    ("compliance_mapping",   seed_compliance_mapping),
    ("container_posture",    seed_container_posture),
    ("container_registry",   seed_container_registry),
    ("container_runtime",    seed_container_runtime),
    ("crypto_keys",          seed_crypto_keys),
    ("cyber_threat_intel",   seed_cyber_threat_intel),
    ("dark_web",             seed_dark_web),
    ("data_discovery",       seed_data_discovery),
    ("data_exfiltration",    seed_data_exfiltration),
    ("data_lake_security",   seed_data_lake_security),
    ("data_pipeline",        seed_data_pipeline),
    ("data_privacy",         seed_data_privacy),
    ("ddos_protection",      seed_ddos_protection),
    ("deception_analytics",  seed_deception_analytics),
    ("digital_identity",     seed_digital_identity),
    ("digital_twin",         seed_digital_twin),
    ("email_filtering",      seed_email_filtering),
    ("endpoint_hunting",     seed_endpoint_hunting),
    ("evidence_vault",       seed_evidence_vault),
    ("feed_subscriptions",   seed_feed_subscriptions),
    ("firewall_policy",      seed_firewall_policy),
    ("firmware_security",    seed_firmware_security),
    ("forensics_readiness",  seed_forensics_readiness),
    ("hunting_automation",   seed_hunting_automation),
    ("identity_risk",        seed_identity_risk),
    ("incident_comms",       seed_incident_comms),
    ("incident_costs",       seed_incident_costs),
    ("ip_reputation",        seed_ip_reputation),
    ("iot_security",         seed_iot_security),
    ("itdr",                 seed_itdr),
    ("ransomware_protection",seed_ransomware_protection),
]


def main():
    print(f"\nALDECI Bulk Engine Seeder — {len(SEEDERS)} engines")
    print(f"  Org ID : {ORG}")
    print(f"  Time   : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

    ok = fail = 0
    for name, fn in SEEDERS:
        try:
            n = fn()
            ok += 1
            print(f"  [OK ] {name}: {n} records")
        except Exception as exc:
            fail += 1
            print(f"  [FAIL] {name}: {exc}")

    print(f"\n  Done: {ok}/{len(SEEDERS)} engines seeded, {fail} failed")
    print(f"  Org ID: {ORG}")


if __name__ == "__main__":
    main()
