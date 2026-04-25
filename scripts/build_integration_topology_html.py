#!/usr/bin/env python3
"""
Build interactive HTML visualisation of the ALDECI TrustGraph integration topology.

Reads ``.aldeci/integration_topology_dump.json`` and renders an interactive
pyvis graph of:

    Tenant  HAS_CONNECTOR  Connector  USES_TOOL  OSSTool  FEEDS_ENGINE  FixopsEngine  EMITS_TO  FindingSource

Color legend (per task spec):
    tenants         = red
    connectors      = teal
    tools           = yellow
    engines         = green
    finding-sources = blue

Each node carries enriched hover metadata (e.g. "Trivy is OSS-replacement-for
Snyk Open Source", "AlertManager-Pro: PCI-DSS regulated SaaS").
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from pyvis.network import Network

REPO = Path(__file__).resolve().parent.parent
DUMP = REPO / ".aldeci" / "integration_topology_dump.json"
OUT_HTML = REPO / "graphify-out-integrations" / "integration-topology.html"

# ---------------------------------------------------------------------------
# Metadata catalogues — these enrich the bare nodes in the dump for the hover
# panel. Keys are the *suffix* portion after the type-prefix in the dump id.
# ---------------------------------------------------------------------------

OSS_TOOL_METADATA: dict[str, dict] = {
    "trivy":              {"label": "Trivy",              "family": "Snyk-OSS / SCA",       "oss_replacement_for": "Snyk Open Source"},
    "falco_trivy":        {"label": "Falco + Trivy",      "family": "Container Runtime",    "oss_replacement_for": "Sysdig Secure / Aqua Runtime"},
    "prowler":            {"label": "Prowler",            "family": "CSPM",                 "oss_replacement_for": "Wiz / Lacework"},
    "owasp_zap":          {"label": "OWASP ZAP",          "family": "DAST",                 "oss_replacement_for": "Burp Suite Enterprise"},
    "wazuh":              {"label": "Wazuh",              "family": "EDR-XDR",              "oss_replacement_for": "CrowdStrike Falcon"},
    "opensearch_wazuh":   {"label": "OpenSearch + Wazuh", "family": "SIEM",                 "oss_replacement_for": "Splunk Enterprise Security"},
    "keycloak_scoutsuite":{"label": "Keycloak + ScoutSuite","family": "IAM",                "oss_replacement_for": "Okta / Auth0"},
    "misp_opencti":       {"label": "MISP + OpenCTI",     "family": "ThreatIntel",          "oss_replacement_for": "Recorded Future / Anomali"},
}

CONNECTOR_FAMILY_BY_SLUG: dict[str, str] = {
    "snyk_oss":     "Snyk-OSS",
    "cspm":         "CSPM",
    "edr_xdr":      "EDR-XDR",
    "siem":         "SIEM",
    "container":    "Container",
    "iam":          "IAM",
    "threat_intel": "ThreatIntel",
    "dast":         "DAST",
}

CONNECTOR_TO_TOOL: dict[str, str] = {
    "snyk_oss":     "trivy",
    "cspm":         "prowler",
    "edr_xdr":      "wazuh",
    "siem":         "opensearch_wazuh",
    "container":    "falco_trivy",
    "iam":          "keycloak_scoutsuite",
    "threat_intel": "misp_opencti",
    "dast":         "owasp_zap",
}

TENANT_METADATA: dict[str, dict] = {
    "altoro-bank":          {"app": "Altoro Mutual (Bank)",      "stack": ".NET / IIS",          "regulated": "FFIEC / SOX"},
    "bodgeit-edu":          {"app": "BodgeIt Store (EdTech)",    "stack": "Java / JSP",          "regulated": "FERPA"},
    "django-vuln-energy":   {"app": "Django-Vuln (Energy Co)",   "stack": "Python / Django",     "regulated": "NERC CIP"},
    "dvwa-mfg":             {"app": "DVWA (Manufacturing)",      "stack": "PHP / MySQL",         "regulated": "ITAR"},
    "graphql-pwn-telecom":  {"app": "GraphQL Pwn (Telecom)",     "stack": "Node / GraphQL",      "regulated": "CPNI"},
    "hackazon-ecom":        {"app": "Hackazon (eCommerce)",      "stack": "PHP / MariaDB",       "regulated": "PCI-DSS"},
    "juice-shop-corp":      {"app": "OWASP Juice Shop (Corp)",   "stack": "Node.js / Angular",   "regulated": "PCI-DSS"},
    "log4shell-pos-grocery":{"app": "Log4Shell POS (Grocery)",   "stack": "Java / Log4j",        "regulated": "PCI-DSS"},
    "nodegoat-retail":      {"app": "NodeGoat (Retail)",         "stack": "Node.js / Express",   "regulated": "PCI-DSS"},
    "petclinic-saas":       {"app": "PetClinic (SaaS)",          "stack": "Java / Spring Boot",  "regulated": "SOC2"},
    "railsgoat-media":      {"app": "RailsGoat (Media)",         "stack": "Ruby on Rails",       "regulated": "DMCA"},
    "ssrf-lab-biotech":     {"app": "SSRF Lab (Biotech)",        "stack": "Python / Flask",      "regulated": "HIPAA / 21 CFR Part 11"},
    "vampi-gov":            {"app": "VAmPI (Gov Agency)",        "stack": "Python / Flask API",  "regulated": "FedRAMP"},
    "vulnado-airlines":     {"app": "Vulnado (Airlines)",        "stack": "Java / Spring",       "regulated": "TSA / DOT"},
    "webgoat-health":       {"app": "WebGoat (Health Insurer)",  "stack": "Java / Spring",       "regulated": "HIPAA"},
}

ENGINE_METADATA: dict[str, dict] = {
    "software_composition_analysis_engine": {"label": "SCA Engine",                    "purpose": "Detects Log4Shell-class CVEs in dependencies"},
    "container_runtime_security_engine":    {"label": "Container Runtime Security",    "purpose": "Runtime kernel-syscall anomaly detection"},
    "cloud_native_security_engine":         {"label": "Cloud-Native Security",         "purpose": "K8s + cloud misconfig posture"},
    "security_event_correlation_engine":    {"label": "Security Event Correlation",    "purpose": "Time-windowed multi-source pattern match"},
    "siem_integration_engine":              {"label": "SIEM Integration",              "purpose": "Normalises CEF/syslog → unified events"},
    "threat_intel_fusion_engine":           {"label": "Threat Intel Fusion",           "purpose": "Consensus IOC scoring across feeds"},
    "identity_risk_engine":                 {"label": "Identity Risk",                 "purpose": "Risk-level scoring per identity"},
    "api_security_mgmt_engine":             {"label": "API Security Mgmt",             "purpose": "OWASP API Top 10 coverage"},
    "security_findings_engine":             {"label": "Security Findings",             "purpose": "Cross-scanner finding deduplication"},
}

FINDING_SOURCE_METADATA: dict[str, dict] = {
    "cve":          {"label": "CVE / NVD",         "feed": "nvd.nist.gov"},
    "epss":         {"label": "EPSS",              "feed": "first.org/epss"},
    "kev":          {"label": "CISA KEV",          "feed": "cisa.gov/kev"},
    "mitre_attack": {"label": "MITRE ATT&CK",      "feed": "attack.mitre.org"},
    "otx":          {"label": "AlienVault OTX",    "feed": "otx.alienvault.com"},
    "abuseipdb":    {"label": "AbuseIPDB",         "feed": "abuseipdb.com"},
    "urlhaus":      {"label": "URLhaus",           "feed": "urlhaus.abuse.ch"},
    "misp_feed":    {"label": "MISP feed",         "feed": "misp-project.org"},
}

# ---------------------------------------------------------------------------
# Color palette per spec
# ---------------------------------------------------------------------------

COLOR = {
    "Tenant":        "#dc2626",  # red
    "Connector":     "#0d9488",  # teal
    "OSSTool":       "#facc15",  # yellow
    "FixopsEngine":  "#16a34a",  # green
    "FindingSource": "#2563eb",  # blue
}

NODE_SIZE = {
    "Tenant":        22,
    "Connector":     8,
    "OSSTool":       28,
    "FixopsEngine":  26,
    "FindingSource": 18,
}


def slug_after_prefix(node_id: str) -> str:
    """`tool_trivy` → `trivy`, `engine_xxx` → `xxx`, `findsrc_cve` → `cve`."""
    for p in ("tool_", "engine_", "findsrc_", "tenant_", "conn_"):
        if node_id.startswith(p):
            return node_id[len(p):]
    return node_id


def connector_parts(conn_id: str) -> tuple[str, str]:
    """`conn_juice-shop-corp__snyk_oss` → ('juice-shop-corp', 'snyk_oss')."""
    body = conn_id[len("conn_"):]
    tenant, _, family = body.partition("__")
    return tenant, family


def build_label(node: dict) -> str:
    nid = node["id"]
    nt = node["type"]
    slug = slug_after_prefix(nid)
    if nt == "Tenant":
        meta = TENANT_METADATA.get(slug, {})
        return meta.get("app", slug)
    if nt == "OSSTool":
        return OSS_TOOL_METADATA.get(slug, {}).get("label", slug)
    if nt == "FixopsEngine":
        return ENGINE_METADATA.get(slug, {}).get("label", slug.replace("_", " ").title())
    if nt == "FindingSource":
        return FINDING_SOURCE_METADATA.get(slug, {}).get("label", slug.upper())
    if nt == "Connector":
        tenant, fam = connector_parts(nid)
        return f"{fam.replace('_','-')}@{tenant}"
    return slug


def build_title(node: dict) -> str:
    """Tooltip / hover panel HTML."""
    nid = node["id"]
    nt = node["type"]
    slug = slug_after_prefix(nid)
    rows = [f"<b>{nt}</b>", f"<code>{nid}</code>"]
    if nt == "Tenant":
        meta = TENANT_METADATA.get(slug, {})
        rows.append(f"App: {meta.get('app', slug)}")
        rows.append(f"Stack: {meta.get('stack', '?')}")
        rows.append(f"Regulated: {meta.get('regulated', '—')}")
    elif nt == "OSSTool":
        meta = OSS_TOOL_METADATA.get(slug, {})
        rows.append(f"Family: {meta.get('family', '?')}")
        rows.append(f"<i>{meta.get('label', slug)} is OSS-replacement-for {meta.get('oss_replacement_for', 'commercial tooling')}</i>")
    elif nt == "FixopsEngine":
        meta = ENGINE_METADATA.get(slug, {})
        rows.append(f"Module: suite-core/core/{slug}.py")
        rows.append(f"Purpose: {meta.get('purpose', 'engine')}")
    elif nt == "FindingSource":
        meta = FINDING_SOURCE_METADATA.get(slug, {})
        rows.append(f"Feed: {meta.get('feed', '?')}")
    elif nt == "Connector":
        tenant, fam = connector_parts(nid)
        tool_slug = CONNECTOR_TO_TOOL.get(fam, "?")
        family_label = CONNECTOR_FAMILY_BY_SLUG.get(fam, fam)
        rows.append(f"Family: {family_label}")
        rows.append(f"Tenant: {tenant}")
        rows.append(f"Backed by OSS tool: <b>{OSS_TOOL_METADATA.get(tool_slug, {}).get('label', tool_slug)}</b>")
    return "<br/>".join(rows)


def build_html(dump_path: Path, out_path: Path) -> tuple[int, int]:
    data = json.loads(dump_path.read_text())
    nodes = data["nodes"]
    edges = data["edges"]

    net = Network(
        height="900px",
        width="100%",
        bgcolor="#0b0f1a",
        font_color="#e5e7eb",
        directed=True,
        notebook=False,
        cdn_resources="in_line",
    )
    # Static layout config — disable physics for stability after initial settle
    net.set_options(
        """
        {
          "nodes": {
            "borderWidth": 1,
            "shape": "dot",
            "font": {"size": 12, "face": "Inter, system-ui, sans-serif"}
          },
          "edges": {
            "color": {"color": "#475569", "opacity": 0.45},
            "arrows": {"to": {"enabled": true, "scaleFactor": 0.5}},
            "smooth": {"type": "dynamic"},
            "width": 0.8
          },
          "physics": {
            "solver": "forceAtlas2Based",
            "forceAtlas2Based": {
              "gravitationalConstant": -55,
              "centralGravity": 0.012,
              "springLength": 110,
              "springConstant": 0.06,
              "damping": 0.85
            },
            "stabilization": {"enabled": true, "iterations": 250, "fit": true},
            "minVelocity": 0.6
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 90,
            "navigationButtons": true,
            "keyboard": true
          }
        }
        """
    )

    for n in nodes:
        nt = n["type"]
        net.add_node(
            n["id"],
            label=build_label(n),
            title=build_title(n),
            color=COLOR.get(nt, "#9ca3af"),
            size=NODE_SIZE.get(nt, 12),
            group=nt,
        )

    rel_color = {
        "HAS_CONNECTOR": "#dc262644",
        "USES_TOOL":     "#facc1566",
        "FEEDS_ENGINE":  "#16a34a99",
        "EMITS_TO":      "#2563eb99",
    }
    for e in edges:
        net.add_edge(
            e["source"],
            e["target"],
            title=e["rel"],
            label="",
            color=rel_color.get(e["rel"], "#475569"),
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Render to string then post-process to inject the legend / info panel.
    html = net.generate_html(notebook=False)

    legend = """
    <div id="aldeci-legend" style="
      position: fixed; top: 14px; right: 14px; z-index: 9999;
      background: rgba(11,15,26,0.92); color: #e5e7eb;
      border: 1px solid #334155; border-radius: 8px; padding: 12px 14px;
      font-family: Inter, system-ui, sans-serif; font-size: 12px; min-width: 220px;
      box-shadow: 0 6px 18px rgba(0,0,0,0.4);">
      <div style="font-weight:600; font-size:13px; margin-bottom:6px;">
        ALDECI Integration Topology
      </div>
      <div style="opacity:.75; margin-bottom:8px;">
        15 tenants × 8 OSS connector families × 8 tools → 9 engines → 8 finding sources
      </div>
      <div style="display:grid; grid-template-columns: 14px auto; gap:4px 8px;">
        <span style="background:#dc2626; width:12px; height:12px; border-radius:50%; display:inline-block;"></span><span>Tenant (regulated app)</span>
        <span style="background:#0d9488; width:12px; height:12px; border-radius:50%; display:inline-block;"></span><span>Connector (per-tenant)</span>
        <span style="background:#facc15; width:12px; height:12px; border-radius:50%; display:inline-block;"></span><span>OSS Tool</span>
        <span style="background:#16a34a; width:12px; height:12px; border-radius:50%; display:inline-block;"></span><span>Fixops Engine</span>
        <span style="background:#2563eb; width:12px; height:12px; border-radius:50%; display:inline-block;"></span><span>Finding Source</span>
      </div>
      <div style="margin-top:10px; opacity:.75;">
        Hover any node for OSS-replacement-for metadata.
      </div>
    </div>
    <div id="aldeci-info" style="
      position: fixed; bottom: 14px; left: 14px; z-index: 9999;
      background: rgba(11,15,26,0.92); color: #e5e7eb;
      border: 1px solid #334155; border-radius: 8px; padding: 12px 14px;
      font-family: Inter, system-ui, sans-serif; font-size: 12px; max-width: 380px;
      box-shadow: 0 6px 18px rgba(0,0,0,0.4); display:none;">
      <div id="aldeci-info-body"></div>
    </div>
    <script>
      // Wire up node-click info panel using the global `network` pyvis exposes.
      window.addEventListener('load', function () {
        function tryWire() {
          if (typeof network === 'undefined' || !network.on) {
            return setTimeout(tryWire, 120);
          }
          var info = document.getElementById('aldeci-info');
          var body = document.getElementById('aldeci-info-body');
          network.on('click', function (params) {
            if (!params.nodes || !params.nodes.length) {
              info.style.display = 'none';
              return;
            }
            var id = params.nodes[0];
            var node = network.body.data.nodes.get(id);
            if (!node) { info.style.display = 'none'; return; }
            body.innerHTML =
              '<div style="font-weight:600; font-size:13px; margin-bottom:6px;">'
              + (node.label || id) + '</div>'
              + (node.title || '');
            info.style.display = 'block';
          });
        }
        tryWire();
      });
    </script>
    """

    html = html.replace("</body>", legend + "\n</body>")
    out_path.write_text(html, encoding="utf-8")
    return len(nodes), len(edges)


def main() -> int:
    if not DUMP.exists():
        print(f"ERROR: dump not found at {DUMP}", file=sys.stderr)
        return 1
    n_nodes, n_edges = build_html(DUMP, OUT_HTML)
    size_kb = OUT_HTML.stat().st_size / 1024
    print(f"OK  nodes={n_nodes} edges={n_edges} html={OUT_HTML} size_kb={size_kb:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
