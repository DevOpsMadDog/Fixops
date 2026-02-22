#!/usr/bin/env python3
"""Dump required fields for failing 422 endpoints from OpenAPI spec."""
import json

spec = json.load(open("/tmp/openapi_dump.json"))
schemas = spec.get("components", {}).get("schemas", {})


def resolve(ref):
    return schemas.get(ref.split("/")[-1], {})


failing = [
    ("POST", "/api/v1/brain/nodes"),
    ("POST", "/api/v1/brain/edges"),
    ("POST", "/api/v1/copilot/sessions"),
    ("POST", "/api/v1/copilot/agents/compliance/gap-analysis"),
    ("POST", "/api/v1/copilot/agents/compliance/map-findings"),
    ("POST", "/api/v1/copilot/agents/orchestrate"),
    ("POST", "/api/v1/copilot/agents/pentest/reachability"),
    ("POST", "/api/v1/copilot/agents/pentest/simulate"),
    ("POST", "/api/v1/copilot/agents/pentest/validate"),
    ("POST", "/api/v1/copilot/agents/remediation/playbook"),
    ("POST", "/api/v1/policies"),
    ("POST", "/api/v1/workflows"),
    ("POST", "/api/v1/remediation/tasks"),
    ("POST", "/api/v1/remediation/sla/check"),
    ("POST", "/api/v1/users"),
    ("POST", "/api/v1/reachability/analyze"),
    ("POST", "/api/v1/reachability/analyze/bulk"),
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
    ("POST", "/api/v1/micro-pentest/batch"),
    ("POST", "/api/v1/micro-pentest/enterprise/scan"),
    ("POST", "/api/v1/mpte/requests"),
    ("POST", "/api/v1/predictions/attack-chain"),
    ("POST", "/api/v1/predictions/combined-analysis"),
    ("POST", "/api/v1/algorithms/gnn/attack-surface"),
    ("POST", "/api/v1/algorithms/gnn/critical-nodes"),
    ("POST", "/api/v1/algorithms/gnn/risk-propagation"),
    ("POST", "/api/v1/collaboration/activities"),
    ("POST", "/api/v1/collaboration/comments"),
    ("POST", "/api/v1/collaboration/notifications/queue"),
    ("GET", "/api/v1/audit/user-activity"),
    ("GET", "/api/v1/collaboration/activities"),
    ("GET", "/api/v1/copilot/agents/compliance/controls/PCI-DSS"),
]

for method, path in failing:
    m = method.lower()
    ep = spec.get("paths", {}).get(path, {}).get(m, {})
    if not ep:
        print(f"\n{method} {path} -> NOT IN SPEC")
        continue

    # Query params
    params = ep.get("parameters", [])
    if params:
        print(f"\n{method} {path} -> QUERY PARAMS:")
        for p in params:
            r = p.get("required", False)
            print(f"  {p.get('name')}: {p.get('schema', {}).get('type', '?')} req={r}")

    rb = ep.get("requestBody", {})
    if not rb:
        if not params:
            print(f"\n{method} {path} -> NO BODY/PARAMS")
        continue

    ct = rb.get("content", {})
    if "multipart/form-data" in ct:
        print(f"\n{method} {path} -> FILE UPLOAD")
        sc = ct["multipart/form-data"].get("schema", {})
        if "$ref" in sc:
            sc = resolve(sc["$ref"])
        for k, v in sc.get("properties", {}).items():
            print(f"  {k}: {v.get('type', v.get('format', '?'))}")
        continue

    jct = ct.get("application/json", {})
    sr = jct.get("schema", {})
    if "$ref" in sr:
        sc = resolve(sr["$ref"])
        nm = sr["$ref"].split("/")[-1]
    else:
        sc = sr
        nm = "inline"

    req = sc.get("required", [])
    props = sc.get("properties", {})
    print(f"\n{method} {path} -> {nm}")
    print(f"  Required: {req}")
    for k, v in props.items():
        if "$ref" in v:
            t = v["$ref"].split("/")[-1]
        elif "allOf" in v:
            t = ",".join([x.get("$ref", "").split("/")[-1] for x in v["allOf"]])
        else:
            t = v.get("type", "?")
        d = v.get("default", "REQ" if k in req else "opt")
        en = v.get("enum", "")
        ex = f" enum={en}" if en else ""
        print(f"  {k}: {t} (d={d}){ex}")
