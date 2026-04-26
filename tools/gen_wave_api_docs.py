"""Generate per-router API reference markdown files from extracted route JSON.

Reads /tmp/routes.json and writes one markdown per router into
docs/api-reference/. Also writes README.md index.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from datetime import datetime

OUT = Path("/Users/devops.ai/fixops/Fixops/docs/api-reference")
OUT.mkdir(parents=True, exist_ok=True)
ROUTES = json.loads(Path("/tmp/routes.json").read_text())

# Map slug -> (Title, summary, source_router_file, persona hints, ui screen hints, related US-IDs)
META = {
    "wave_a": {
        "title": "Wave A — Code & Architecture Intelligence",
        "summary": "17 endpoints across Graph, Deep Code Analysis (DCA), Reachability, Components, IDE Gateway, and Runtime Telemetry.",
        "source": "suite-api/apps/api/wave_a_code_intel_router.py",
        "personas": "AppSec Engineer, Platform Engineer, Developer (IDE), Architect",
        "ui_screens": [
            "ArchAwareGraphDashboard.tsx",
            "ReachabilityDashboard.tsx",
            "ComponentsDashboard.tsx",
            "IDEExtensionDashboard.tsx",
            "RuntimeTelemetryDashboard.tsx",
        ],
        "user_stories": ["US-0008", "US-0010", "US-0012", "US-0013", "US-0014", "US-0024", "US-0026", "US-0029", "US-0047", "US-0065"],
    },
    "wave_b": {
        "title": "Wave B — Findings, Risk & Scoring",
        "summary": "16 endpoints covering finding lifecycle, scoring explainability, SBOM monitoring, and investigations.",
        "source": "suite-api/apps/api/findings_wave_b_router.py",
        "personas": "AppSec Lead, SOC Analyst, Risk Manager",
        "ui_screens": [
            "FindingsDashboard.tsx",
            "ScoringExplainability.tsx",
            "SBOMMonitoringDashboard.tsx",
            "InvestigationsConsole.tsx",
        ],
        "user_stories": ["US-0006", "US-0021", "US-0043", "US-0055", "US-0062", "US-0063"],
    },
    "wave_c": {
        "title": "Wave C — System, Org, PBOM, Provenance & Admin",
        "summary": "21 endpoints across system health, org tree, PBOM extras, provenance attestation, change tracking, scopes, air-gap, admin/user tokens, CSPM, skills, rules, and LLM cost-routing.",
        "source": "suite-api/apps/api/wave_c_router.py",
        "personas": "Platform Admin, Compliance Lead, SecOps Engineer",
        "ui_screens": [
            "OrgHierarchyDashboard.tsx",
            "PBOMConsole.tsx",
            "ProvenanceAttestationDashboard.tsx",
            "AirGapBundleDashboard.tsx",
            "AdminTokensDashboard.tsx",
            "UserTokensDashboard.tsx",
            "RuleAuthoringConsole.tsx",
        ],
        "user_stories": ["US-0001", "US-0002", "US-0003", "US-0004", "US-0005", "US-0007", "US-0011", "US-0017", "US-0018", "US-0039", "US-0042", "US-0061", "US-0064", "US-0066", "US-0067", "US-0068", "US-0069"],
    },
    "wave_d": {
        "title": "Wave D — Connectors, Webhooks, EASM, Copilot & Policies",
        "summary": "20 endpoints for universal connector field-mapping, webhook event-catalogue + subscriptions, external attack-surface seeding, NL graph copilot, AI exposure, AI Teammates, asset crown-jewel tagging, TrustGraph compaction, waiver lifecycle, and policy stage-matrices.",
        "source": "suite-api/apps/api/wave_d_integrations_router.py",
        "personas": "Integration Engineer, AI Security Lead, Policy Author",
        "ui_screens": [
            "ConnectorMappingUI.tsx",
            "WebhookCatalogueDashboard.tsx",
            "EASMDashboard.tsx",
            "GraphCopilotDashboard.tsx",
            "AIExposureDashboard.tsx",
            "AITeammatesConsole.tsx",
            "PolicyStageMatrixEditor.tsx",
        ],
        "user_stories": ["US-0030", "US-0034", "US-0038", "US-0044", "US-0046", "US-0059"],
    },
    "privilege_escalation_detector": {
        "title": "Privilege Escalation Detector",
        "summary": "Detects privilege escalation events, AD attack-paths, and rule heatmaps.",
        "source": "suite-api/apps/api/privilege_escalation_detector_router.py",
        "personas": "IAM Engineer, SOC Analyst",
        "ui_screens": ["PrivilegeEscalationDashboard.tsx"],
        "user_stories": ["US-0021"],
    },
    "mitre_attack_coverage": {
        "title": "MITRE ATT&CK Coverage",
        "summary": "Coverage analytics: techniques inventoried, detection mappings, gap analysis, heatmaps.",
        "source": "suite-api/apps/api/mitre_attack_coverage_router.py",
        "personas": "Detection Engineer, SOC Lead",
        "ui_screens": ["MITRECoverageDashboard.tsx"],
        "user_stories": [],
    },
    "duckdb_analytics": {
        "title": "DuckDB Cross-Domain Analytics",
        "summary": "Cross-domain SQL analytics over the 60+ embedded SQLite engines via DuckDB.",
        "source": "suite-api/apps/api/duckdb_analytics_router.py",
        "personas": "Risk Analyst, Executive Reporting",
        "ui_screens": ["ExecutiveDashboard.tsx", "RiskSummaryDashboard.tsx"],
        "user_stories": [],
    },
    "verification": {
        "title": "Multi-Stage Verification",
        "summary": "Multi-stage signature/identity verification engine.",
        "source": "suite-api/apps/api/verification_router.py",
        "personas": "Security Engineer, Compliance Lead",
        "ui_screens": ["VerificationDashboard.tsx"],
        "user_stories": [],
    },
    "intelligent_security": {
        "title": "Intelligent Security Engine",
        "summary": "Session-bound NL intelligence, assessment, and graph queries.",
        "source": "suite-api/apps/api/intelligent_security_router.py",
        "personas": "Security Analyst",
        "ui_screens": ["IntelligentSecurityConsole.tsx"],
        "user_stories": [],
    },
    "graphrag": {
        "title": "GraphRAG",
        "summary": "Graph-based retrieval-augmented generation over TrustGraph cores with traced query history.",
        "source": "suite-api/apps/api/graphrag_router.py",
        "personas": "Security Analyst, AI Engineer",
        "ui_screens": ["GraphRAGConsole.tsx"],
        "user_stories": ["US-0029"],
    },
    "context_engine": {
        "title": "Context Engine",
        "summary": "Evaluates contextual signals (asset, exposure, business) for an enrichment decision.",
        "source": "suite-api/apps/api/context_engine_router.py",
        "personas": "Risk Engineer",
        "ui_screens": ["ContextEnrichmentDashboard.tsx"],
        "user_stories": [],
    },
}


def example_curl(ep, base="http://localhost:8000"):
    method = ep["method"]
    path = ep["path"]
    auth = '-H "X-API-Key: $ALDECI_API_KEY" '
    org = '-H "X-Org-ID: $ALDECI_ORG_ID" ' if path.startswith("/api/v1") else ""
    if method == "GET":
        return f'curl -sS {auth}{org}"{base}{path}"'
    if ep.get("body_type"):
        body = '\'{"example": "payload — see schema for full shape"}\''
    else:
        body = "'{}'"
    return f'curl -sS -X {method} {auth}{org}-H "Content-Type: application/json" -d {body} "{base}{path}"'


def render_endpoint(ep):
    method = ep["method"]
    path = ep["path"]
    doc = ep["doc"] or "_(undocumented)_"
    auth = "Required (`X-API-Key`)" if ep["auth"] else "None (public)"
    sc = ep["status_code"] or (201 if method == "POST" and "create" in ep["func"].lower() else 200)
    body = ep.get("body_type") or "_None_"
    lines = [
        f"### `{method} {path}`",
        "",
        doc,
        "",
        f"- **Auth**: {auth}",
        f"- **Handler**: `{ep['func']}`",
        f"- **Request body**: `{body}`",
        f"- **Success**: `{sc}` JSON",
        "- **Common errors**: `400` validation, `401` missing/invalid API key, `403` org mismatch, `404` resource missing, `500` engine failure",
        "",
        "**Example**",
        "",
        "```bash",
        example_curl(ep),
        "```",
        "",
    ]
    return "\n".join(lines)


def render_router_doc(slug, eps, meta):
    by_tag = {}
    for ep in eps:
        tag = (ep["tags"][0] if ep["tags"] else "Untagged")
        by_tag.setdefault(tag, []).append(ep)

    parts = [
        f"# {meta['title']}",
        "",
        f"_Auto-generated {datetime.utcnow().strftime('%Y-%m-%d')} from `{meta['source']}`._",
        "",
        meta["summary"],
        "",
        f"- **Endpoints**: {len(eps)}",
        f"- **Personas**: {meta['personas']}",
        f"- **Auth**: API key (`X-API-Key`) on all `/api/v1/*` routes; tenant scope via `X-Org-ID` header",
        f"- **UI screens**: {', '.join(f'`{s}`' for s in meta['ui_screens'])}",
        f"- **User stories**: {', '.join(meta['user_stories']) if meta['user_stories'] else '_n/a_'}",
        "",
        "## Endpoint Index",
        "",
        "| Method | Path | Description |",
        "|---|---|---|",
    ]
    for ep in eps:
        d = (ep["doc"] or "").replace("|", "\\|")
        parts.append(f"| `{ep['method']}` | `{ep['path']}` | {d} |")
    parts.append("")

    for tag, group in by_tag.items():
        parts.append(f"## {tag}")
        parts.append("")
        for ep in group:
            parts.append(render_endpoint(ep))

    parts += [
        "## Error Codes",
        "",
        "| Status | Meaning |",
        "|---|---|",
        "| 200 | Success (GET, idempotent POST) |",
        "| 201 | Created (POST resource creation) |",
        "| 202 | Accepted (async task enqueued) |",
        "| 400 | Validation failed — malformed JSON or schema violation |",
        "| 401 | Missing or invalid `X-API-Key` |",
        "| 403 | API key valid but lacks org/role scope |",
        "| 404 | Resource not found |",
        "| 409 | Conflict — resource already exists or state violation |",
        "| 422 | Pydantic validation error (FastAPI default) |",
        "| 429 | Rate limit exceeded |",
        "| 500 | Engine error — see `detail` |",
        "| 501 | Endpoint stubbed for an engine that is not yet wired |",
        "",
        "## Notes",
        "",
        f"- Generated by `tools/extract_routes.py` from `{meta['source']}`. Re-run after router changes.",
        "- Schemas marked `_None_` do not accept a request body. Path/query params are typed in the source.",
        "- For request body shapes, consult the Pydantic models in the router source file or the live OpenAPI spec at `GET /openapi.json`.",
        "",
    ]
    return "\n".join(parts)


# Write per-router docs
written = []
for slug, eps in ROUTES.items():
    meta = META[slug]
    doc = render_router_doc(slug, eps, meta)
    p = OUT / f"{slug}.md"
    p.write_text(doc)
    written.append((slug, len(eps), p))

# Index README
total = sum(len(v) for v in ROUTES.values())
idx = [
    "# ALDECI API Reference — Wave A/B/C/D + Engine Routers",
    "",
    f"_Auto-generated {datetime.utcnow().strftime('%Y-%m-%d')}._",
    "",
    f"**Total endpoints documented in this set: {total}** (plus pre-existing endpoints documented in `../API_REFERENCE.md`)",
    "",
    "This directory contains per-router API reference docs for the four Multica delivery waves and the seven supporting engine routers.",
    "",
    "## How to use",
    "",
    "1. Find your domain in the table below.",
    "2. Click into the per-router doc.",
    "3. Each endpoint has: HTTP method + path, auth requirement, request body type, success status, common 4xx/5xx codes, and a working `curl` example.",
    "4. UI integration: each doc lists the React `.tsx` page(s) that consume the endpoints.",
    "",
    "## Index",
    "",
    "| Doc | Endpoints | Source Router | Personas |",
    "|---|---|---|---|",
]
for slug, eps in ROUTES.items():
    m = META[slug]
    idx.append(f"| [{m['title']}]({slug}.md) | {len(eps)} | `{m['source']}` | {m['personas']} |")
idx += [
    "",
    "## Authentication (applies to all)",
    "",
    "```http",
    "X-API-Key: <your-api-key>",
    "X-Org-ID: <your-org-id>     # optional but recommended for multi-tenant",
    "```",
    "",
    "Live OpenAPI spec: `GET /openapi.json` · Swagger UI: `GET /docs` · ReDoc: `GET /redoc`",
    "",
    "## Wave Roadmap",
    "",
    "- **Wave A** — Code & Architecture intelligence (DCA, reachability, IDE, runtime).",
    "- **Wave B** — Finding lifecycle, scoring explainability, continuous SBOM, investigations.",
    "- **Wave C** — System / org tree / PBOM / provenance / changes / air-gap / admin / CSPM / rules / LLM cost-routing.",
    "- **Wave D** — Connectors, webhooks, EASM, NL copilot, AI exposure, AI Teammates, policies.",
    "- **Engine routers** — Standalone engines that ship endpoints independently of waves: privilege escalation, MITRE coverage, DuckDB analytics, verification, intelligent security, GraphRAG, context engine.",
    "",
    "## Cross-references",
    "",
    "- Top-level reference: [`../API_REFERENCE.md`](../API_REFERENCE.md)",
    "- v2 reference: [`../API_REFERENCE_v2.md`](../API_REFERENCE_v2.md)",
    "- Architecture: [`../ARCHITECTURE_v3.md`](../ARCHITECTURE_v3.md)",
    "- CTEM+ identity: [`../CTEM_PLUS_IDENTITY.md`](../CTEM_PLUS_IDENTITY.md)",
    "- Postman collection: [`../ALDECI_Postman_Collection.json`](../ALDECI_Postman_Collection.json)",
    "",
]
(OUT / "README.md").write_text("\n".join(idx))

print(f"Wrote {len(written)} per-router docs + 1 index ({total} endpoints total)")
for slug, n, p in written:
    print(f"  {p.name} — {n} endpoints")
