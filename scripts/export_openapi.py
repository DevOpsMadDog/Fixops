#!/usr/bin/env python3
"""Export the ALDECI OpenAPI spec to docs/openapi.json.

Usage:
    cd /Users/devops.ai/fixops/Fixops
    python scripts/export_openapi.py

The generated file is suitable for import into Postman, Swagger UI,
or any OpenAPI-compatible tooling.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Ensure suite paths are on sys.path (mirrors sitecustomize.py behaviour)
_repo_root = Path(__file__).resolve().parent.parent
for _suite in ("suite-api", "suite-core", "suite-attack", "suite-feeds", "suite-evidence-risk", "suite-integrations"):
    _p = str(_repo_root / _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Minimal env so create_app() doesn't fail in a bare shell
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "export-script")
os.environ.setdefault("FIXOPS_JWT_SECRET", "export-script-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from apps.api.app import create_app  # noqa: E402

app = create_app()
spec = app.openapi()

out_path = _repo_root / "docs" / "openapi.json"
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path, "w") as f:
    json.dump(spec, f, indent=2)

endpoint_count = sum(len(methods) for methods in spec.get("paths", {}).values())
print(f"OpenAPI spec exported to {out_path}")
print(f"  Paths   : {len(spec.get('paths', {}))}")
print(f"  Endpoints: {endpoint_count}")
print(f"  Version : {spec.get('info', {}).get('version', 'unknown')}")
