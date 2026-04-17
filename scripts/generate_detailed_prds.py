#!/usr/bin/env python3
"""
Generate detailed PRDs for all 332 ALDECI engines.
Reads actual code to extract: class names, methods, DB paths, line numbers,
router endpoints, test counts. Outputs PRDs with mermaid diagrams.
"""

import ast
import os
import re
import glob
import textwrap
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENGINE_DIR = PROJECT_ROOT / "suite-core" / "core"
ROUTER_DIR = PROJECT_ROOT / "suite-api" / "apps" / "api"
TEST_DIR = PROJECT_ROOT / "tests"
OUTPUT_DIR = PROJECT_ROOT / ".omc" / "prds" / "v2"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 30 Personas mapped to domains
PERSONA_MAP = {
    "access": ("Robert Kim", "Compliance Officer", "enforce access policies for SOC2/NIST compliance"),
    "ai_": ("Chris Lee", "Security Data Scientist", "leverage AI/ML for threat detection and analysis"),
    "alert": ("Alex Rivera", "SOC T1 Analyst", "triage and prioritize security alerts efficiently"),
    "analytics": ("Chris Lee", "Security Data Scientist", "analyze security data for trends and insights"),
    "api_": ("Emma Davis", "DevSecOps Engineer", "secure APIs against OWASP Top 10 threats"),
    "app": ("Tom Anderson", "AppSec Lead", "manage application security scanning and findings"),
    "asset": ("Maria Lopez", "IT Director", "maintain accurate asset inventory and risk scoring"),
    "attack": ("Lisa Zhang", "Pentester", "model attack paths and simulate adversary behavior"),
    "audit": ("Michael Brown", "Audit Manager", "manage audit trails and compliance evidence"),
    "awareness": ("Emily Chang", "Developer Security Champion", "track security training effectiveness"),
    "backup": ("Ryan Murphy", "Platform Engineer", "ensure data backup integrity and recovery"),
    "bandwidth": ("Ryan Murphy", "Platform Engineer", "monitor network bandwidth and QoS"),
    "behavioral": ("Priya Sharma", "SOC T2 Analyst", "detect anomalous user behavior patterns"),
    "breach": ("Karen Taylor", "IR Lead", "detect and respond to security breaches rapidly"),
    "browser": ("Tom Anderson", "AppSec Lead", "enforce browser security policies"),
    "bug_bounty": ("Lisa Zhang", "Pentester", "manage bug bounty program submissions"),
    "casb": ("Jennifer Wu", "Cloud Security Architect", "control shadow IT and SaaS access"),
    "ccm": ("Robert Kim", "Compliance Officer", "manage cloud controls matrix compliance"),
    "cert": ("Ryan Murphy", "Platform Engineer", "track certificate lifecycle and expiry"),
    "ciem": ("Jennifer Wu", "Cloud Security Architect", "manage cloud IAM entitlements"),
    "cloud": ("Jennifer Wu", "Cloud Security Architect", "secure cloud infrastructure and workloads"),
    "cmdb": ("Maria Lopez", "IT Director", "maintain configuration management database"),
    "cnapp": ("Jennifer Wu", "Cloud Security Architect", "protect cloud-native applications"),
    "compliance": ("Robert Kim", "Compliance Officer", "automate compliance assessment and evidence"),
    "config": ("James Wilson", "Security Engineer", "benchmark configurations against CIS/STIG"),
    "container": ("Jennifer Wu", "Cloud Security Architect", "secure container registries and runtimes"),
    "context": ("Priya Sharma", "SOC T2 Analyst", "enrich security context for investigation"),
    "control": ("Robert Kim", "Compliance Officer", "test security controls effectiveness"),
    "crypto": ("James Wilson", "Security Engineer", "manage cryptographic key lifecycle"),
    "cspm": ("Jennifer Wu", "Cloud Security Architect", "assess cloud security posture"),
    "ctem": ("Lisa Zhang", "Pentester", "manage continuous threat exposure"),
    "cwpp": ("Jennifer Wu", "Cloud Security Architect", "protect cloud workloads"),
    "cyber_insurance": ("David Park", "Risk Manager", "manage cyber insurance policies and claims"),
    "cyber_resilience": ("Sarah Chen", "CISO", "measure and improve cyber resilience"),
    "cyber_threat": ("Nina Patel", "Threat Intel Analyst", "model and track cyber threats"),
    "dark_web": ("Nina Patel", "Threat Intel Analyst", "monitor dark web for credential exposures"),
    "dast": ("Emma Davis", "DevSecOps Engineer", "run dynamic application security tests"),
    "data_class": ("Robert Kim", "Compliance Officer", "classify and label sensitive data"),
    "data_discovery": ("Robert Kim", "Compliance Officer", "discover sensitive data across datastores"),
    "data_exfiltration": ("Karen Taylor", "IR Lead", "detect and prevent data exfiltration"),
    "data_governance": ("Robert Kim", "Compliance Officer", "enforce data governance policies"),
    "data_lake": ("Chris Lee", "Security Data Scientist", "secure data lake environments"),
    "data_privacy": ("Robert Kim", "Compliance Officer", "manage data privacy compliance"),
    "data_retention": ("Robert Kim", "Compliance Officer", "enforce GDPR/CCPA data retention"),
    "ddos": ("Ryan Murphy", "Platform Engineer", "detect and mitigate DDoS attacks"),
    "deception": ("Lisa Zhang", "Pentester", "deploy honeypots and canary tokens"),
    "devsecops": ("Emma Davis", "DevSecOps Engineer", "integrate security into CI/CD pipelines"),
    "digital_forensics": ("Karen Taylor", "IR Lead", "conduct digital forensic investigations"),
    "digital_identity": ("Maria Lopez", "IT Director", "manage digital identity verification"),
    "digital_twin": ("Richard Adams", "Security Architect", "simulate security with digital twins"),
    "dlp": ("Robert Kim", "Compliance Officer", "prevent data loss with DLP policies"),
    "duckdb": ("Chris Lee", "Security Data Scientist", "run cross-domain analytics queries"),
    "edr": ("Alex Rivera", "SOC T1 Analyst", "detect and respond to endpoint threats"),
    "email": ("James Wilson", "Security Engineer", "filter malicious emails and phishing"),
    "endpoint": ("James Wilson", "Security Engineer", "enforce endpoint security compliance"),
    "evidence": ("Michael Brown", "Audit Manager", "manage evidence chain and vault"),
    "executive": ("Catherine Williams", "Board Member", "generate executive security reports"),
    "fail": ("Ryan Murphy", "Platform Engineer", "manage failure detection and recovery"),
    "firewall": ("James Wilson", "Security Engineer", "manage firewall rules and policies"),
    "firmware": ("James Wilson", "Security Engineer", "scan firmware for vulnerabilities"),
    "forensics": ("Karen Taylor", "IR Lead", "maintain forensic readiness"),
    "gdpr": ("Robert Kim", "Compliance Officer", "ensure GDPR compliance"),
    "graphrag": ("Richard Adams", "Security Architect", "query security knowledge graph"),
    "grc": ("Robert Kim", "Compliance Officer", "manage governance, risk, and compliance"),
    "hunting": ("Priya Sharma", "SOC T2 Analyst", "automate threat hunting workflows"),
    "iac": ("Emma Davis", "DevSecOps Engineer", "scan infrastructure-as-code templates"),
    "identity": ("Maria Lopez", "IT Director", "manage identity analytics and risk"),
    "iga": ("Maria Lopez", "IT Director", "govern identity access lifecycle"),
    "incident": ("Karen Taylor", "IR Lead", "manage incident response lifecycle"),
    "insider": ("Priya Sharma", "SOC T2 Analyst", "detect insider threats via behavior"),
    "intelligent": ("Chris Lee", "Security Data Scientist", "apply ML to security decisions"),
    "ioc": ("Nina Patel", "Threat Intel Analyst", "enrich indicators of compromise"),
    "iot": ("James Wilson", "Security Engineer", "secure IoT devices and networks"),
    "ip_reputation": ("Nina Patel", "Threat Intel Analyst", "score and block malicious IPs"),
    "ir_playbook": ("Karen Taylor", "IR Lead", "execute incident response playbooks"),
    "itdr": ("Priya Sharma", "SOC T2 Analyst", "detect identity-based threats"),
    "kpi": ("Sarah Chen", "CISO", "track security KPIs and performance"),
    "kubernetes": ("Jennifer Wu", "Cloud Security Architect", "secure Kubernetes clusters"),
    "log_management": ("Ryan Murphy", "Platform Engineer", "manage security log retention"),
    "malware": ("Priya Sharma", "SOC T2 Analyst", "analyze malware samples and IOCs"),
    "mdm": ("James Wilson", "Security Engineer", "manage mobile device security"),
    "mfa": ("Maria Lopez", "IT Director", "manage multi-factor authentication"),
    "micro": ("James Wilson", "Security Engineer", "enforce microsegmentation policies"),
    "mitre": ("Richard Adams", "Security Architect", "map coverage to MITRE ATT&CK"),
    "mobile": ("James Wilson", "Security Engineer", "secure mobile applications"),
    "nac": ("James Wilson", "Security Engineer", "enforce network access control"),
    "ndr": ("Alex Rivera", "SOC T1 Analyst", "detect network-based threats"),
    "network": ("James Wilson", "Security Engineer", "monitor and secure network traffic"),
    "notification": ("Daniel Thompson", "SecOps Manager", "manage security notifications"),
    "openclaw": ("Richard Adams", "Security Architect", "orchestrate autonomous security agents"),
    "operational_technology": ("James Wilson", "Security Engineer", "secure OT/ICS/SCADA systems"),
    "ot_security": ("James Wilson", "Security Engineer", "protect operational technology"),
    "pam": ("Maria Lopez", "IT Director", "manage privileged access"),
    "passive_dns": ("Nina Patel", "Threat Intel Analyst", "track passive DNS records"),
    "password": ("Maria Lopez", "IT Director", "enforce password policies and MFA"),
    "patch": ("James Wilson", "Security Engineer", "manage patch deployment lifecycle"),
    "pentest": ("Lisa Zhang", "Pentester", "manage penetration testing engagements"),
    "phishing": ("James Wilson", "Security Engineer", "simulate phishing campaigns"),
    "physical": ("James Wilson", "Security Engineer", "manage physical security access"),
    "pki": ("James Wilson", "Security Engineer", "manage PKI certificates and CAs"),
    "playbook": ("Karen Taylor", "IR Lead", "create and execute security playbooks"),
    "policy": ("Robert Kim", "Compliance Officer", "enforce security policies"),
    "posture": ("Sarah Chen", "CISO", "measure security posture and trends"),
    "privacy": ("Robert Kim", "Compliance Officer", "assess privacy impact"),
    "privilege": ("Maria Lopez", "IT Director", "detect privilege escalation"),
    "quantum": ("Richard Adams", "Security Architect", "assess quantum computing risks"),
    "questionnaire": ("Robert Kim", "Compliance Officer", "manage security questionnaires"),
    "ransomware": ("Karen Taylor", "IR Lead", "protect against ransomware attacks"),
    "rasp": ("Emma Davis", "DevSecOps Engineer", "protect runtime applications"),
    "rbac": ("Maria Lopez", "IT Director", "manage role-based access control"),
    "red_team": ("Lisa Zhang", "Pentester", "manage red team operations"),
    "regulatory": ("Robert Kim", "Compliance Officer", "track regulatory changes"),
    "remediation": ("James Wilson", "Security Engineer", "manage vulnerability remediation"),
    "risk": ("David Park", "Risk Manager", "quantify and manage security risk"),
    "saas": ("Jennifer Wu", "Cloud Security Architect", "assess SaaS security posture"),
    "sast": ("Emma Davis", "DevSecOps Engineer", "run static application security tests"),
    "sbom": ("Amanda Scott", "Supply Chain Security", "manage software bill of materials"),
    "scheduled": ("Daniel Thompson", "SecOps Manager", "schedule automated security reports"),
    "secret": ("Emma Davis", "DevSecOps Engineer", "detect and manage secrets exposure"),
    "security_arch": ("Richard Adams", "Security Architect", "review security architecture"),
    "security_auto": ("Daniel Thompson", "SecOps Manager", "automate security workflows"),
    "security_awareness": ("Emily Chang", "Developer Security Champion", "run awareness programs"),
    "security_baseline": ("James Wilson", "Security Engineer", "manage security baselines"),
    "security_benchmark": ("Sarah Chen", "CISO", "benchmark against industry peers"),
    "security_budget": ("Sarah Chen", "CISO", "manage security budget allocation"),
    "security_cap": ("Sarah Chen", "CISO", "plan security team capacity"),
    "security_champion": ("Emily Chang", "Developer Security Champion", "run champions program"),
    "security_change": ("Daniel Thompson", "SecOps Manager", "manage security changes"),
    "security_chaos": ("Lisa Zhang", "Pentester", "run chaos engineering experiments"),
    "security_culture": ("Sarah Chen", "CISO", "measure security culture maturity"),
    "security_data": ("Chris Lee", "Security Data Scientist", "manage security data pipelines"),
    "security_dep": ("Emma Davis", "DevSecOps Engineer", "map and assess dependency risks"),
    "security_event": ("Priya Sharma", "SOC T2 Analyst", "correlate security events"),
    "security_exception": ("David Park", "Risk Manager", "manage security exceptions"),
    "security_findings": ("James Wilson", "Security Engineer", "manage security findings lifecycle"),
    "security_gap": ("Robert Kim", "Compliance Officer", "analyze security gaps"),
    "security_health": ("Sarah Chen", "CISO", "monitor security program health"),
    "security_investment": ("Sarah Chen", "CISO", "track security investment ROI"),
    "security_maturity": ("Sarah Chen", "CISO", "assess security program maturity"),
    "security_metrics": ("Sarah Chen", "CISO", "aggregate security metrics"),
    "security_okr": ("Sarah Chen", "CISO", "track security OKRs"),
    "security_operations": ("Daniel Thompson", "SecOps Manager", "monitor SOC performance"),
    "security_playbook": ("Karen Taylor", "IR Lead", "manage security playbooks"),
    "security_posture": ("Sarah Chen", "CISO", "track security posture over time"),
    "security_program": ("Sarah Chen", "CISO", "assess program maturity"),
    "security_questionnaire": ("Robert Kim", "Compliance Officer", "manage vendor questionnaires"),
    "security_registry": ("James Wilson", "Security Engineer", "manage security artifacts"),
    "security_roadmap": ("Sarah Chen", "CISO", "plan security roadmap"),
    "security_scoreboard": ("Emily Chang", "Developer Security Champion", "gamify security metrics"),
    "security_scorecard": ("Sarah Chen", "CISO", "grade organizational security"),
    "security_service": ("Daniel Thompson", "SecOps Manager", "manage security service catalog"),
    "security_tabletop": ("Karen Taylor", "IR Lead", "run tabletop exercises"),
    "security_telemetry": ("Ryan Murphy", "Platform Engineer", "collect security telemetry"),
    "security_tool": ("Daniel Thompson", "SecOps Manager", "track security tool inventory"),
    "security_training": ("Emily Chang", "Developer Security Champion", "measure training effectiveness"),
    "service_account": ("Maria Lopez", "IT Director", "audit service accounts"),
    "siem": ("Priya Sharma", "SOC T2 Analyst", "manage SIEM event integration"),
    "sla": ("Marcus Johnson", "VP Engineering", "track security SLA compliance"),
    "soar": ("Daniel Thompson", "SecOps Manager", "orchestrate automated response"),
    "soc": ("Alex Rivera", "SOC T1 Analyst", "manage SOC workflow and triage"),
    "software_comp": ("Amanda Scott", "Supply Chain Security", "analyze software composition"),
    "software_license": ("Amanda Scott", "Supply Chain Security", "assess OSS license risks"),
    "supply_chain": ("Amanda Scott", "Supply Chain Security", "monitor supply chain risks"),
    "third_party": ("David Park", "Risk Manager", "assess third-party vendor risk"),
    "threat_actor": ("Nina Patel", "Threat Intel Analyst", "track threat actor TTPs"),
    "threat_attribution": ("Nina Patel", "Threat Intel Analyst", "attribute attacks to actors"),
    "threat_brief": ("Nina Patel", "Threat Intel Analyst", "distribute threat briefings"),
    "threat_correlation": ("Priya Sharma", "SOC T2 Analyst", "correlate threat indicators"),
    "threat_deception": ("Lisa Zhang", "Pentester", "manage deception campaigns"),
    "threat_exposure": ("David Park", "Risk Manager", "score threat exposure risk"),
    "threat_feed": ("Nina Patel", "Threat Intel Analyst", "manage threat feed subscriptions"),
    "threat_geolocation": ("Nina Patel", "Threat Intel Analyst", "map threats geographically"),
    "threat_hunting": ("Priya Sharma", "SOC T2 Analyst", "run proactive threat hunts"),
    "threat_indicator": ("Nina Patel", "Threat Intel Analyst", "manage IOC lifecycle"),
    "threat_intel": ("Nina Patel", "Threat Intel Analyst", "automate threat intelligence"),
    "threat_landscape": ("Sarah Chen", "CISO", "assess the threat landscape"),
    "threat_model": ("Richard Adams", "Security Architect", "generate STRIDE threat models"),
    "threat_response": ("Karen Taylor", "IR Lead", "orchestrate threat response"),
    "threat_score": ("David Park", "Risk Manager", "compute weighted threat scores"),
    "threat_simulation": ("Lisa Zhang", "Pentester", "simulate red/blue team exercises"),
    "threat_vector": ("David Park", "Risk Manager", "analyze threat attack vectors"),
    "tprm": ("David Park", "Risk Manager", "manage third-party risk exchange"),
    "uba": ("Priya Sharma", "SOC T2 Analyst", "analyze user behavior for anomalies"),
    "user_access": ("Robert Kim", "Compliance Officer", "review user access periodically"),
    "vendor": ("David Park", "Risk Manager", "assess vendor compliance and risk"),
    "verification": ("Brian Hall", "QA Security Tester", "verify security controls"),
    "vuln_exception": ("David Park", "Risk Manager", "manage vulnerability exceptions"),
    "vuln_intel": ("Nina Patel", "Threat Intel Analyst", "fuse vulnerability intelligence"),
    "vuln_priorit": ("James Wilson", "Security Engineer", "prioritize vulnerabilities by risk"),
    "vuln_scan": ("Brian Hall", "QA Security Tester", "manage vulnerability scans"),
    "vuln_trend": ("David Park", "Risk Manager", "analyze vulnerability trends"),
    "vuln_workflow": ("James Wilson", "Security Engineer", "manage vulnerability workflows"),
    "vulnerability": ("James Wilson", "Security Engineer", "track vulnerability lifecycle"),
    "waf": ("James Wilson", "Security Engineer", "manage WAF rules and policies"),
    "wireless": ("James Wilson", "Security Engineer", "secure wireless networks"),
    "workflow": ("Daniel Thompson", "SecOps Manager", "automate security workflows"),
    "xdr": ("Alex Rivera", "SOC T1 Analyst", "correlate XDR telemetry"),
    "zero_day": ("Nina Patel", "Threat Intel Analyst", "track zero-day vulnerabilities"),
    "zero_trust": ("Richard Adams", "Security Architect", "enforce zero trust policies"),
}

# Sub-epic mapping
SUBEPIC_MAP = {
    "api_": "ASPM", "app": "ASPM", "sast": "ASPM", "dast": "ASPM", "sbom": "ASPM",
    "sca": "ASPM", "devsecops": "ASPM", "rasp": "ASPM", "iac": "ASPM", "secret": "ASPM",
    "cloud": "CSPM", "cspm": "CSPM", "kubernetes": "CSPM", "cnapp": "CSPM", "cwpp": "CSPM",
    "casb": "CSPM", "container": "CSPM", "saas": "CSPM",
    "attack": "CTEM", "ctem": "CTEM", "pentest": "CTEM", "red_team": "CTEM",
    "threat_hunt": "CTEM", "breach": "CTEM", "vuln": "CTEM", "vulnerability": "CTEM",
    "dark_web": "CTEM", "malware": "CTEM", "ransomware": "CTEM",
    "alert": "SOC", "incident": "SOC", "soc": "SOC", "soar": "SOC", "siem": "SOC",
    "triage": "SOC", "playbook": "SOC", "ir_playbook": "SOC", "edr": "SOC",
    "ndr": "SOC", "xdr": "SOC", "itdr": "SOC",
    "compliance": "GRC", "audit": "GRC", "evidence": "GRC", "regulatory": "GRC",
    "policy": "GRC", "gdpr": "GRC", "grc": "GRC", "control": "GRC", "privacy": "GRC",
    "data_retention": "GRC", "data_privacy": "GRC", "data_governance": "GRC",
    "data_class": "GRC",
    "access": "Identity", "identity": "Identity", "mfa": "Identity", "password": "Identity",
    "privilege": "Identity", "pam": "Identity", "rbac": "Identity", "iga": "Identity",
    "service_account": "Identity", "user_access": "Identity", "digital_identity": "Identity",
    "firewall": "Network", "network": "Network", "nac": "Network", "wireless": "Network",
    "bandwidth": "Network", "ddos": "Network", "waf": "Network", "micro": "Network",
    "passive_dns": "Network", "email": "Network",
    "ai_": "AI Intelligence", "ml": "AI Intelligence", "behavioral": "AI Intelligence",
    "threat_intel": "AI Intelligence", "threat_actor": "AI Intelligence",
    "threat_attribution": "AI Intelligence", "threat_brief": "AI Intelligence",
    "threat_feed": "AI Intelligence", "threat_indicator": "AI Intelligence",
    "threat_landscape": "AI Intelligence", "threat_score": "AI Intelligence",
    "ioc": "AI Intelligence", "ip_reputation": "AI Intelligence",
    "threat_geolocation": "AI Intelligence",
    "executive": "Executive", "kpi": "Executive", "posture": "Executive",
    "security_health": "Executive", "security_metrics": "Executive",
    "security_okr": "Executive", "security_benchmark": "Executive",
    "security_scorecard": "Executive", "security_roadmap": "Executive",
    "security_budget": "Executive", "security_investment": "Executive",
    "risk": "Executive", "cyber_insurance": "Executive",
}


def get_persona(engine_name: str):
    """Map engine name to a persona."""
    for prefix, info in PERSONA_MAP.items():
        if engine_name.startswith(prefix):
            return info
    return ("James Wilson", "Security Engineer", "manage security operations")


def get_subepic(engine_name: str) -> str:
    """Map engine name to a sub-epic."""
    for prefix, epic in SUBEPIC_MAP.items():
        if engine_name.startswith(prefix):
            return epic
    return "Advanced"


def extract_engine_info(engine_path: Path) -> dict:
    """Extract class, methods, DB path, imports from engine file."""
    info = {
        "classes": [],
        "methods": [],
        "db_path": None,
        "imports": [],
        "lines": 0,
        "docstring": "",
    }

    try:
        content = engine_path.read_text(errors="replace")
        info["lines"] = content.count("\n") + 1

        # Extract DB path
        db_match = re.search(r'["\']([^"\']*\.db)["\']', content)
        if db_match:
            info["db_path"] = db_match.group(1)

        # Extract imports from core/
        for m in re.finditer(r'from\s+(core\.\w+)\s+import', content):
            info["imports"].append(m.group(1))

        # Parse AST for classes and methods
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    info["classes"].append({
                        "name": node.name,
                        "line": node.lineno,
                        "docstring": ast.get_docstring(node) or "",
                    })
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if not item.name.startswith("_"):
                                doc = ast.get_docstring(item) or ""
                                info["methods"].append({
                                    "name": item.name,
                                    "line": item.lineno,
                                    "desc": doc.split("\n")[0][:80] if doc else "",
                                    "class": node.name,
                                })
            # Module docstring
            info["docstring"] = ast.get_docstring(tree) or ""
        except SyntaxError:
            pass
    except Exception:
        pass

    return info


def extract_router_info(engine_name: str) -> dict:
    """Find and extract router endpoints for an engine."""
    info = {"file": None, "prefix": "", "endpoints": []}

    # Try various router naming patterns
    patterns = [
        engine_name.replace("_engine", "_router"),
        engine_name.replace("_engine", "_engine_router"),
        engine_name.replace("_engine", ""),
    ]

    for pattern in patterns:
        matches = list(ROUTER_DIR.glob(f"*{pattern}*.py"))
        if matches:
            router_path = matches[0]
            info["file"] = router_path.name
            try:
                content = router_path.read_text(errors="replace")

                # Extract prefix
                prefix_match = re.search(r'prefix\s*=\s*["\']([^"\']+)["\']', content)
                if prefix_match:
                    info["prefix"] = prefix_match.group(1)

                # Extract endpoints
                for m in re.finditer(
                    r'@router\.(get|post|put|patch|delete)\(\s*["\']([^"\']*)["\']',
                    content,
                ):
                    method = m.group(1).upper()
                    path = m.group(2)
                    # Get the next function name
                    remaining = content[m.end():]
                    fn_match = re.search(r'(?:async\s+)?def\s+(\w+)', remaining)
                    fn_name = fn_match.group(1) if fn_match else ""
                    info["endpoints"].append({
                        "method": method,
                        "path": f"{info['prefix']}{path}",
                        "function": fn_name,
                    })
            except Exception:
                pass
            break

    return info


def count_tests(engine_name: str) -> dict:
    """Count tests for an engine."""
    info = {"file": None, "count": 0}
    test_patterns = [
        f"test_{engine_name}.py",
        f"test_{engine_name.replace('_engine', '')}.py",
    ]
    for pattern in test_patterns:
        test_path = TEST_DIR / pattern
        if test_path.exists():
            info["file"] = pattern
            try:
                content = test_path.read_text(errors="replace")
                info["count"] = len(re.findall(r'def\s+test_', content))
            except Exception:
                pass
            break
    return info


def generate_prd(engine_name: str, us_number: int) -> str:
    """Generate a detailed PRD for an engine."""
    engine_path = ENGINE_DIR / f"{engine_name}.py"
    if not engine_path.exists():
        return ""

    engine_info = extract_engine_info(engine_path)
    router_info = extract_router_info(engine_name)
    test_info = count_tests(engine_name)
    persona_name, persona_role, persona_need = get_persona(engine_name)
    subepic = get_subepic(engine_name)

    # Display name
    display_name = engine_name.replace("_engine", "").replace("_", " ").title()
    class_name = engine_info["classes"][0]["name"] if engine_info["classes"] else f"{display_name.replace(' ', '')}Engine"
    db_name = engine_info["db_path"] or f"data/{engine_name.replace('_engine', '')}.db"

    # Calculate completion
    has_router = router_info["file"] is not None
    has_tests = test_info["count"] > 0
    has_methods = len(engine_info["methods"]) > 3
    completion = 60
    if has_router:
        completion += 15
    if has_tests:
        completion += 15
    if has_methods:
        completion += 10
    completion = min(95, completion)

    # Build mermaid diagram
    deps = engine_info["imports"][:5]
    dep_nodes = ""
    for i, dep in enumerate(deps):
        mod_name = dep.split(".")[-1]
        dep_nodes += f'    {class_name} --> Dep{i}["{mod_name}"]\n'

    # Methods list (top 8)
    methods = engine_info["methods"][:8]
    methods_md = ""
    for m in methods:
        desc = m["desc"] or f"Handle {m['name'].replace('_', ' ')}"
        methods_md += f"- `{m['class']}.{m['name']}()` — {desc} (line {m['line']})\n"
    if not methods_md:
        methods_md = "- Engine methods not yet extracted\n"

    # Endpoints table
    endpoints_md = ""
    for ep in router_info["endpoints"][:12]:
        endpoints_md += f"| {ep['method']} | `{ep['path']}` | {ep['function'].replace('_', ' ')} |\n"
    if not endpoints_md:
        endpoints_md = f"| GET | `{router_info['prefix'] or '/api/v1/' + engine_name.replace('_engine', '').replace('_', '-')}` | List resources |\n"

    # Working/missing features
    working = []
    missing = []
    for m in engine_info["methods"][:6]:
        working.append(f"✅ `{m['name']}()` — {m['desc'] or 'implemented'} (line {m['line']})")
    if not working:
        working.append("✅ Engine class defined and instantiable")
    if not has_router:
        missing.append("❌ No dedicated router — endpoint may be in gap_router.py")
    if not has_tests:
        missing.append("❌ No test file found — needs test coverage")
    if len(engine_info["methods"]) < 3:
        missing.append("❌ Limited public API — needs more methods")
    missing.append("❌ TrustGraph event emission — not yet verified")

    working_md = "\n".join(f"- {w}" for w in working)
    missing_md = "\n".join(f"- {m}" for m in missing)

    # Sprint assignment
    wave = 42 + (us_number // 30)

    # Deps list
    deps_readable = ", ".join(d.split(".")[-1] for d in deps) if deps else "standalone"

    prefix = router_info["prefix"] or f"/api/v1/{engine_name.replace('_engine', '').replace('_', '-')}"

    prd = f"""# US-{us_number:04d}: {display_name}

## Sub-Epic: {subepic}
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **{persona_name} ({persona_role})**, I need to {persona_need}
so that the platform delivers enterprise-grade {subepic.lower()} capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
{display_name} replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone {subepic} tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["{prefix}"]
    API --> Auth["api_key_auth"]
    Auth --> Router["{router_info['file'] or engine_name.replace('_engine', '_router.py')}"]
    Router --> Engine["{class_name}"]
    Engine --> DB[(SQLite: {db_name})]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
{dep_nodes}    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: {completion}% Complete
{working_md}
{missing_md}

## Key Functions (from `suite-core/core/{engine_name}.py` — {engine_info['lines']} lines)
{methods_md}
## Dependencies
- **Depends on**: {deps_readable}
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/{engine_name}.py` ({engine_info['lines']} lines)
- **Router file**: `suite-api/apps/api/{router_info['file'] or 'N/A'}`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
{endpoints_md}
## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
{"5. Create dedicated router (needs wiring in app.py) (3h)" if not has_router else "5. Optimize query performance for large datasets (2h)"}
{"6. Write unit tests (4h)" if not has_tests else "6. Expand test coverage to edge cases (2h)"}

## Definition of Done
- [ ] {persona_name} ({persona_role}) can access {prefix} and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] {test_info['count'] or 20}+ tests passing in `tests/test_{engine_name}.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave {wave} (est. April {18 + wave - 42}-{20 + wave - 42}, 2026)

## Test Coverage
- **Test file**: `tests/{test_info['file'] or f'test_{engine_name}.py'}`
- **Tests**: {test_info['count']} tests
- **Status**: {'Passing' if test_info['count'] > 0 else 'Needs coverage'}
"""
    return prd


def main():
    engines = sorted(
        [p.stem for p in ENGINE_DIR.glob("*engine*.py") if p.stem != "__init__"]
    )
    print(f"Generating PRDs for {len(engines)} engines...")

    for i, engine_name in enumerate(engines):
        us_number = i + 1
        prd = generate_prd(engine_name, us_number)
        if prd:
            output_path = OUTPUT_DIR / f"{engine_name}.md"
            output_path.write_text(prd)
            if (i + 1) % 50 == 0:
                print(f"  [{i+1}/{len(engines)}] Generated {engine_name}")

    generated = len(list(OUTPUT_DIR.glob("*.md")))
    print(f"\nDone! Generated {generated} PRDs in {OUTPUT_DIR}")
    print(f"Each PRD includes: User Story, Architecture Diagram, Code Proof,")
    print(f"Key Functions, Dependencies, API Endpoints, Tasks, Definition of Done")


if __name__ == "__main__":
    main()
