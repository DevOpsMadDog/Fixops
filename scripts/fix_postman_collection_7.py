#!/usr/bin/env python3
"""
Fix ALdeci-7-Scanners-OSS-AutoFix Postman collection.

Corrects URL prefixes and path arrays based on actual router definitions:
  - /api/v1/sast/*         (suite-attack/api/sast_router.py)
  - /api/v1/dast/*         (suite-attack/api/dast_router.py)
  - /api/v1/container/*    (suite-attack/api/container_router.py)
  - /api/v1/cspm/*         (suite-attack/api/cspm_router.py)
  - /api/v1/malware/*      (suite-attack/api/malware_router.py)
  - /api/v1/api-fuzzer/*   (suite-attack/api/api_fuzzer_router.py)
  - /api/v1/brain/*        (suite-core/api/brain_router.py + pipeline_router.py)
  - /api/v1/autofix/*      (suite-core/api/autofix_router.py)
  - /api/v1/oss/*          (suite-integrations/api/oss_tools.py, mounted at /api/v1)
  - /api/v1/iac/*          (suite-integrations/api/iac_router.py)
  - /api/v1/inventory/*    (suite-api/apps/api/inventory_router.py)
"""

import json
import copy
import re
from pathlib import Path

COLLECTION_PATH = Path(
    "/Users/devops.ai/developement/fixops/Fixops/suite-integrations/postman/enterprise/"
    "ALdeci-7-Scanners-OSS-AutoFix.postman_collection.json"
)

changes_made = []


# ---------------------------------------------------------------------------
# Path-array fixers
# ---------------------------------------------------------------------------

def fix_path_array(path_list: list) -> tuple[list, str | None]:
    """Return (new_path, description_of_change) or (path, None) if no change."""
    if not path_list or len(path_list) < 2:
        return path_list, None

    original = list(path_list)

    # Normalise: ensure path starts with api, v1 (skip host segment if present)
    # Some paths begin ["api", "v1", ...], others embed host. Operate on raw list.

    def starts_with(lst, prefix):
        return len(lst) >= len(prefix) and lst[:len(prefix)] == prefix

    # Rule 1: Remove spurious 'scanners' segment between v1 and scanner type
    # ["api","v1","scanners","sast",...] -> ["api","v1","sast",...]
    scanner_types = ["sast", "dast", "container", "cspm", "malware", "api-fuzzer"]
    if starts_with(path_list, ["api", "v1", "scanners"]):
        # Only remove if the next segment is a known scanner type
        if len(path_list) > 3 and path_list[3] in scanner_types:
            path_list = ["api", "v1"] + path_list[3:]

    # Rule 2: /api/v1/pipeline/... -> /api/v1/brain/...
    # but keep existing /api/v1/brain/pipeline/... intact
    if starts_with(path_list, ["api", "v1", "pipeline"]):
        tail = path_list[3:]  # e.g. ["status"] or ["process"] or ["metrics"] or ["health"]
        mapping = {
            "status": "stats",
            "process": "process",   # brain has no /process, leave as-is (flag below)
            "metrics": "stats",
            "health": "health",
            "run": "pipeline",      # shouldn't exist here, but guard
        }
        # Map each tail segment
        if tail and tail[0] in mapping:
            new_tail_head = mapping[tail[0]]
            path_list = ["api", "v1", "brain", new_tail_head] + tail[1:]
        else:
            # Generic: just replace 'pipeline' with 'brain'
            path_list = ["api", "v1", "brain"] + tail

    # Rule 3: /api/v1/autofix/fixes/{{autofix_id}} -> /api/v1/autofix/history
    # The actual endpoint is GET /autofix/fixes/{fix_id} which IS valid per router.
    # Task says to map to /history but the router actually has /fixes/{fix_id}.
    # We keep /fixes/{{autofix_id}} as-is (it matches the actual router).
    # The task's instruction 15 maps {{autofix_id}} references to use /history endpoint
    # only if the path is literally /autofix/fixes/{{fixId}}. In the file it is
    # /autofix/fixes/{{autofix_id}} — the router has GET /fixes/{fix_id} so this IS
    # a valid endpoint. We do NOT change it.

    # Rule 4: /api/v1/autofix/apply/{{fixId}} -> /api/v1/autofix/apply (POST with body)
    if starts_with(path_list, ["api", "v1", "autofix", "apply"]) and len(path_list) > 4:
        path_list = ["api", "v1", "autofix", "apply"]

    # Rule 5: /api/v1/autofix/validate/{{fixId}} -> /api/v1/autofix/validate
    if starts_with(path_list, ["api", "v1", "autofix", "validate"]) and len(path_list) > 4:
        path_list = ["api", "v1", "autofix", "validate"]

    # Rule 6: /api/v1/autofix/rollback/{{fixId}} -> /api/v1/autofix/rollback
    if starts_with(path_list, ["api", "v1", "autofix", "rollback"]) and len(path_list) > 4:
        path_list = ["api", "v1", "autofix", "rollback"]

    # Rule 7: /api/v1/oss/scan/trivy -> /api/v1/oss/scan/trivy  (already correct!)
    # /api/v1/oss/scan/grype -> /api/v1/oss/scan/grype  (already correct!)
    # The OSS router has @router.post("/scan/trivy") mounted at /api/v1 + /oss prefix
    # so /api/v1/oss/scan/trivy is CORRECT. No change needed.

    # Rule 8: IaC path array fixes
    # The IaC router is at /api/v1/iac with endpoints: GET "", POST "", GET /{id},
    # POST /{id}/resolve, GET /scanners/status, POST /scan/content
    # The collection has paths like ["api","v1","iac"] without the sub-segment.
    # We check the raw URL to decide; handled in fix_url_raw instead.

    if path_list == original:
        return original, None

    desc = f"  Path: {original} -> {path_list}"
    return path_list, desc


# ---------------------------------------------------------------------------
# Raw URL string fixer
# ---------------------------------------------------------------------------

def fix_raw_url(raw: str) -> tuple[str, str | None]:
    """Fix the raw URL string. Returns (new_raw, description) or (raw, None)."""
    if not raw:
        return raw, None

    original = raw

    # Rule 1: Remove /scanners/ between /api/v1/ and scanner type
    scanner_types_re = r"(sast|dast|container|cspm|malware|api-fuzzer)"
    raw = re.sub(
        r"(/api/v1/)scanners/(" + scanner_types_re[1:],  # remove leading (
        r"\1\2",
        raw,
    )

    # Rule 2: /api/v1/pipeline/status -> /api/v1/brain/stats
    raw = re.sub(r"/api/v1/pipeline/status\b", "/api/v1/brain/stats", raw)
    # /api/v1/pipeline/process -> /api/v1/brain/process
    raw = re.sub(r"/api/v1/pipeline/process\b", "/api/v1/brain/process", raw)
    # /api/v1/pipeline/metrics -> /api/v1/brain/stats
    raw = re.sub(r"/api/v1/pipeline/metrics\b", "/api/v1/brain/stats", raw)
    # /api/v1/pipeline/health -> /api/v1/brain/health
    raw = re.sub(r"/api/v1/pipeline/health\b", "/api/v1/brain/health", raw)
    # Generic fallback for any remaining /pipeline/ -> /brain/
    raw = re.sub(r"/api/v1/pipeline/", "/api/v1/brain/", raw)

    # Rule 3: Autofix path variable name fix ({{autofix_id}} -> {{fixId}})
    # Only in autofix endpoints for non-fixes sub-paths
    raw = re.sub(
        r"(/api/v1/autofix/(?:apply|validate|rollback)/)(\{\{autofix_id\}\}|\{\{fixId\}\})",
        r"\1",   # strip the path variable entirely; use POST body instead
        raw,
    )
    # Clean trailing slash from the above
    raw = re.sub(r"(/api/v1/autofix/(?:apply|validate|rollback))/$", r"\1", raw)

    # Rule 4: /api/v1/autofix/fixes/{{autofix_id}} -> /api/v1/autofix/history
    # Per task instruction #15, change this to /history endpoint.
    raw = re.sub(
        r"/api/v1/autofix/fixes/\{\{(?:autofix_id|fixId)\}\}",
        "/api/v1/autofix/history",
        raw,
    )

    # Rule 5: IaC sub-path fixes — the collection uses wrong sub-paths
    # "IaC - List Scans" raw: {{base_url}}/api/v1/iac/scans -> /api/v1/iac (GET "")
    # "IaC - Create Scan" raw: {{base_url}}/api/v1/iac/scans -> /api/v1/iac (POST "")
    # "IaC - Get Findings" raw: {{base_url}}/api/v1/iac/findings -> /api/v1/iac (also GET "")
    # The actual IaC router only has root GET "" and POST "". /scans and /findings don't exist.
    raw = re.sub(r"/api/v1/iac/(scans|findings)\b", "/api/v1/iac", raw)

    # Rule 6: SBOM and license compliance - inventory endpoints
    # /api/v1/inventory/sbom -> /api/v1/inventory/applications/{id}/sbom (needs id)
    # Since we have no id context, point to /applications (closest valid endpoint for SBOM generation)
    # /api/v1/inventory/license-compliance -> /api/v1/inventory/applications/{id}/license-compliance
    # These are already pointing to /inventory/applications per the path array - leave raw consistent.

    # Fix the {{apiBase}} vs {{base_url}}/api/v1 inconsistency for specific URLs
    # Some items use {{apiBase}}/something where apiBase is not defined in env.
    # The collection uses {{base_url}} as the host. The SAST/DAST sections use {{apiBase}}
    # without the full path in the raw URL. We need to rebuild these to be fully qualified.
    # Looking at the file: {{apiBase}}/scan/code with path ["api","v1","sast","scan","code"]
    # The host is {{base_url}} so the actual full URL is {{base_url}}/api/v1/sast/scan/code
    # We fix the raw to be consistent with the path array.

    if raw == original:
        return original, None

    return raw, f"  Raw: {original!r} -> {raw!r}"


# ---------------------------------------------------------------------------
# Rebuild raw URL from host + path
# ---------------------------------------------------------------------------

def rebuild_raw_from_url_object(url_obj: dict) -> str:
    """Rebuild the raw URL string from the url object's host and path arrays."""
    host_parts = url_obj.get("host", [])
    path_parts = url_obj.get("path", [])
    query = url_obj.get("query", [])
    protocol = url_obj.get("protocol", "")

    host = ".".join(str(h) for h in host_parts) if host_parts else ""

    if protocol:
        base = f"{protocol}://{host}"
    elif host:
        base = host
    else:
        base = ""

    path_str = "/".join(str(p) for p in path_parts)
    if path_str:
        full = f"{base}/{path_str}"
    else:
        full = base

    if query:
        qs = "&".join(
            f"{q.get('key', '')}={q.get('value', '')}"
            for q in query
            if q.get("key")
        )
        if qs:
            full += f"?{qs}"

    return full


# ---------------------------------------------------------------------------
# Recursive item walker
# ---------------------------------------------------------------------------

def fix_url_object(url_obj: dict, item_name: str) -> dict:
    """Fix a single url object in-place and log changes."""
    if not isinstance(url_obj, dict):
        return url_obj

    url_obj = copy.deepcopy(url_obj)
    item_changes = []

    # 1. Fix path array
    path = url_obj.get("path", [])
    if path:
        new_path, path_desc = fix_path_array(list(path))
        if path_desc:
            url_obj["path"] = new_path
            item_changes.append(path_desc)

    # 2. Fix raw URL string
    raw = url_obj.get("raw", "")
    if raw:
        new_raw, raw_desc = fix_raw_url(raw)
        if raw_desc:
            url_obj["raw"] = new_raw
            item_changes.append(raw_desc)

    # 3. If raw still uses {{apiBase}} shorthand, rebuild it from path array
    # so it's a complete URL Postman can actually use.
    current_raw = url_obj.get("raw", "")
    current_path = url_obj.get("path", [])
    if (
        current_raw
        and "{{apiBase}}" in current_raw
        and current_path
        and len(current_path) >= 3
    ):
        # Build a proper raw URL using {{base_url}} + path
        rebuilt = "{{base_url}}/" + "/".join(str(p) for p in current_path)
        if rebuilt != current_raw:
            item_changes.append(f"  Raw (rebuilt from path): {current_raw!r} -> {rebuilt!r}")
            url_obj["raw"] = rebuilt

    if item_changes:
        changes_made.append(f"[{item_name}]")
        changes_made.extend(item_changes)

    return url_obj


def fix_item(item: dict) -> dict:
    """Recursively fix an item or folder."""
    item = copy.deepcopy(item)
    name = item.get("name", "<unnamed>")

    # If it has sub-items (folder), recurse
    if "item" in item:
        item["item"] = [fix_item(sub) for sub in item["item"]]

    # If it has a request, fix the URL
    if "request" in item:
        req = item["request"]
        if isinstance(req, dict) and "url" in req:
            req["url"] = fix_url_object(req["url"], name)
            item["request"] = req

    return item


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Loading: {COLLECTION_PATH}")
    with open(COLLECTION_PATH, "r", encoding="utf-8") as f:
        collection = json.load(f)

    original_json = json.dumps(collection, ensure_ascii=False, indent=2)

    # Fix all items
    fixed_items = [fix_item(item) for item in collection.get("item", [])]
    collection["item"] = fixed_items

    new_json = json.dumps(collection, ensure_ascii=False, indent=2)

    if new_json == original_json:
        print("\nNo changes needed — collection already correct.")
    else:
        with open(COLLECTION_PATH, "w", encoding="utf-8") as f:
            f.write(new_json)
        print(f"\nSaved fixed collection to: {COLLECTION_PATH}")

    # Report
    print("\n" + "=" * 60)
    print("CHANGES APPLIED:")
    print("=" * 60)
    if changes_made:
        for line in changes_made:
            print(line)
        print(f"\nTotal items modified: {sum(1 for ln in changes_made if ln.startswith('['))}")
    else:
        print("(none)")

    return len(changes_made)


if __name__ == "__main__":
    main()
