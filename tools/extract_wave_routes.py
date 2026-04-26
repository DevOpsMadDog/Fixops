"""Extract endpoints from wave routers via AST.

Avoids importing FastAPI app (heavy). Pulls @router.METHOD("path", ...) calls
and the function defs that follow, plus router prefix/tags.
"""
from __future__ import annotations
import ast, json, re, sys
from pathlib import Path

ROUTERS = [
    ("wave_a", "wave_a_code_intel_router.py"),
    ("wave_b", "findings_wave_b_router.py"),
    ("wave_c", "wave_c_router.py"),
    ("wave_d", "wave_d_integrations_router.py"),
    ("privilege_escalation_detector", "privilege_escalation_detector_router.py"),
    ("mitre_attack_coverage", "mitre_attack_coverage_router.py"),
    ("duckdb_analytics", "duckdb_analytics_router.py"),
    ("verification", "verification_router.py"),
    ("intelligent_security", "intelligent_security_router.py"),
    ("graphrag", "graphrag_router.py"),
    ("context_engine", "context_engine_router.py"),
]
ROOT = Path("/Users/devops.ai/fixops/Fixops/suite-api/apps/api")

def _str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None

def parse_router_call(call):
    # Returns dict(prefix, tags, name) for an APIRouter(...) call
    prefix = ""
    tags = []
    for kw in call.keywords:
        if kw.arg == "prefix":
            v = _str(kw.value)
            if v: prefix = v
        if kw.arg == "tags" and isinstance(kw.value, ast.List):
            tags = [_str(e) for e in kw.value.elts if _str(e)]
    return {"prefix": prefix, "tags": tags}

def extract(filepath: Path):
    """Walk module, locate router = APIRouter(...) and route decorators."""
    src = filepath.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(src, filename=str(filepath))

    # Find router assignments: name -> (prefix, tags)
    routers: dict[str, dict] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and isinstance(node.value, ast.Call):
                    fn = node.value.func
                    if (isinstance(fn, ast.Name) and fn.id == "APIRouter") or \
                       (isinstance(fn, ast.Attribute) and fn.attr == "APIRouter"):
                        routers[tgt.id] = parse_router_call(node.value)

    endpoints = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            fn = dec.func
            if not isinstance(fn, ast.Attribute):
                continue
            if fn.attr.lower() not in {"get","post","put","delete","patch"}:
                continue
            obj = fn.value
            router_name = obj.id if isinstance(obj, ast.Name) else None
            r_meta = routers.get(router_name, {"prefix": "", "tags": []})
            # path arg
            path = ""
            if dec.args:
                p = _str(dec.args[0])
                if p: path = p
            # local tags override
            local_tags = list(r_meta["tags"])
            for kw in dec.keywords:
                if kw.arg == "tags" and isinstance(kw.value, ast.List):
                    local_tags = [_str(e) for e in kw.value.elts if _str(e)]
            # status_code, dependencies presence
            deps_auth = False
            status_code = None
            for kw in dec.keywords:
                if kw.arg == "status_code" and isinstance(kw.value, ast.Constant):
                    status_code = kw.value.value
                if kw.arg == "dependencies":
                    src_seg = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                    if "api_key" in src_seg or "auth" in src_seg or "Auth" in src_seg:
                        deps_auth = True
            # docstring
            doc = ast.get_docstring(node) or ""
            # function args -> request body type if Pydantic class is used
            body_type = None
            for a in node.args.args:
                if a.annotation is not None:
                    ann = ast.unparse(a.annotation) if hasattr(ast, "unparse") else ""
                    if any(t in ann for t in ("Request","Body","Model","Payload","Input","Spec","Config")) and a.arg not in {"request"}:
                        body_type = ann
                        break
            endpoints.append({
                "method": fn.attr.upper(),
                "path": (r_meta["prefix"] + path) or path,
                "tags": local_tags,
                "func": node.name,
                "doc": doc.split("\n")[0].strip() if doc else "",
                "auth": deps_auth or "/api/v1" in (r_meta["prefix"] + path),
                "status_code": status_code,
                "body_type": body_type,
            })
    return endpoints

result = {}
for slug, fname in ROUTERS:
    fp = ROOT / fname
    if not fp.exists():
        continue
    result[slug] = extract(fp)

print(json.dumps(result, indent=2))
