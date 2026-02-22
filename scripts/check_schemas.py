#!/usr/bin/env python3
import json
import urllib.request

resp = urllib.request.urlopen("http://127.0.0.1:8000/openapi.json")
spec = json.loads(resp.read())
paths = spec.get("paths", {})
schemas = spec.get("components", {}).get("schemas", {})


def resolve_ref(ref):
    name = ref.split("/")[-1]
    s = schemas.get(name, {})
    props = s.get("properties", {})
    required = s.get("required", [])
    prop_info = {}
    for k, v in list(props.items())[:12]:
        t = v.get("type", "")
        r = v.get("$ref", "")
        if r:
            t = "ref:" + r.split("/")[-1]
        prop_info[k] = t
    return name, required, prop_info


fails = [
    ("POST", "/api/v1/vulns/contribute"),
    ("POST", "/api/v1/secrets/scan/content"),
    ("POST", "/api/v1/iac/scan/content"),
    ("POST", "/api/v1/api-fuzzer/fuzz"),
    ("POST", "/api/v1/api-fuzzer/discover"),
    ("POST", "/api/v1/deduplication/correlations"),
    ("POST", "/api/v1/brain/nodes"),
    ("POST", "/api/v1/brain/edges"),
    ("POST", "/api/v1/predictions/attack-chain"),
    ("POST", "/api/v1/predictions/combined-analysis"),
    ("POST", "/api/v1/algorithms/gnn/risk-propagation"),
    ("POST", "/api/v1/algorithms/gnn/critical-nodes"),
    ("POST", "/api/v1/algorithms/gnn/attack-surface"),
    ("POST", "/api/v1/micro-pentest/enterprise/scan"),
    ("POST", "/api/v1/micro-pentest/batch"),
    ("POST", "/api/v1/mpte/requests"),
    ("POST", "/api/v1/reachability/analyze"),
    ("POST", "/api/v1/reachability/analyze/bulk"),
    ("POST", "/api/v1/remediation/tasks"),
    ("POST", "/api/v1/remediation/sla/check"),
    ("GET", "/api/v1/audit/user-activity"),
    ("POST", "/api/v1/policies"),
    ("POST", "/api/v1/workflows"),
    ("POST", "/api/v1/copilot/sessions"),
    ("POST", "/api/v1/copilot/agents/compliance/gap-analysis"),
    ("POST", "/api/v1/copilot/agents/compliance/map-findings"),
    ("GET", "/api/v1/copilot/agents/compliance/controls/{framework}"),
    ("POST", "/api/v1/copilot/agents/pentest/validate"),
    ("POST", "/api/v1/copilot/agents/pentest/simulate"),
    ("POST", "/api/v1/copilot/agents/pentest/reachability"),
    ("POST", "/api/v1/copilot/agents/remediation/playbook"),
    ("POST", "/api/v1/copilot/agents/orchestrate"),
    ("GET", "/api/v1/collaboration/activities"),
    ("POST", "/api/v1/collaboration/comments"),
    ("POST", "/api/v1/collaboration/activities"),
    ("POST", "/api/v1/collaboration/notifications/queue"),
    ("POST", "/api/v1/marketplace/contribute"),
    ("POST", "/api/v1/identity/resolve"),
    ("POST", "/api/v1/identity/resolve/batch"),
    ("POST", "/api/v1/enhanced/analysis"),
    ("POST", "/api/v1/enhanced/compare-llms"),
    ("POST", "/api/v1/intelligent-engine/intelligence/gather"),
    ("POST", "/api/v1/intelligent-engine/consensus/analyze"),
    ("POST", "/api/v1/intelligent-engine/plan/generate"),
    ("POST", "/api/v1/bulk/findings/update"),
    ("POST", "/api/v1/bulk/findings/assign"),
    ("POST", "/api/v1/bulk/export"),
    ("POST", "/api/v1/validate/input"),
    ("POST", "/api/v1/validate/batch"),
    ("POST", "/inputs/cve"),
    ("POST", "/inputs/sarif"),
    ("POST", "/inputs/sbom"),
    ("POST", "/api/v1/feeds/exploits"),
    ("POST", "/api/v1/feeds/threat-actors"),
    ("POST", "/api/v1/feeds/supply-chain"),
    ("POST", "/api/v1/business-context/validate"),
    ("POST", "/api/v1/users"),
    ("GET", "/api/v1/ide/suggestions"),
    ("POST", "/api/v1/integrations"),
]

for method, path in fails:
    m = method.lower()
    p = paths.get(path, {})
    op = p.get(m, {})
    body = op.get("requestBody", {})
    params = op.get("parameters", [])
    content = body.get("content", {}).get("application/json", {})
    schema_info = content.get("schema", {})
    schema_ref = schema_info.get("$ref", "")
    if schema_ref:
        name, req, props = resolve_ref(schema_ref)
        print(f"{method} {path}")
        print(f"  Schema: {name}")
        print(f"  Required: {req}")
        print(f"  Props: {props}")
    elif params:
        pinfo = [
            (p.get("name"), p.get("required", False), p.get("in")) for p in params[:5]
        ]
        print(f"{method} {path}")
        print(f"  Params: {pinfo}")
    elif schema_info:
        props = schema_info.get("properties", {})
        req = schema_info.get("required", [])
        print(f"{method} {path}")
        print(f"  Inline required: {req}")
        print(f"  Inline props: {list(props.keys())[:10]}")
    else:
        print(f"{method} {path} -> NO SCHEMA FOUND")
    print()
