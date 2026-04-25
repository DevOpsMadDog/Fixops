#!/usr/bin/env python3
"""Generate real SBOMs for 15 fleet tenants via /api/v1/sbom-export/components.

Parses package.json / package-lock.json / pyproject.toml / requirements.txt /
pom.xml / build.gradle / go.mod for each repo and POSTs every component to
the real ingestion API. No DB writes.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable

API = "http://localhost:8000"
KEY = os.environ.get(
    "FIXOPS_API_KEY",
    "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_",
)
FLEET = Path("/tmp/fixops-fleet")

# slug | display | repo-dir | language | project_name (== repo dir)
TENANTS = [
    ("juice-shop-corp", "juice-shop", "javascript"),
    ("node-goat-inc", "NodeGoat", "javascript"),
    ("webgoat-llc", "WebGoat", "java"),
    ("vulnado-co", "vulnado", "java"),
    ("dvna-systems", "dvna", "javascript"),
    ("express-corp", "express", "javascript"),
    ("fastify-inc", "fastify", "javascript"),
    ("axios-llc", "axios", "javascript"),
    ("lodash-co", "lodash", "javascript"),
    ("requests-corp", "requests", "python"),
    ("fastapi-inc", "fastapi", "python"),
    ("flask-llc", "flask", "python"),
    ("django-corp", "django", "python"),
    ("httpx-co", "httpx", "python"),
    ("anthropic-sdk-corp", "anthropic-sdk-python", "python"),
]


# --------------------------------------------------------------------------- #
# Manifest parsers — each yields (name, version, ecosystem, license)
# --------------------------------------------------------------------------- #
def _strip_npm_range(spec: str) -> str:
    """Convert ^1.2.3 / ~1.2 / >=1.0 / 1.x → 1.2.3 / 1.2.0 / 1.0.0 / 1.0.0."""
    if not spec or not isinstance(spec, str):
        return "0.0.0"
    s = spec.strip().lstrip("^~>=<* ").rstrip(" *")
    s = re.split(r"[\s|,<>=]+", s, maxsplit=1)[0]
    s = s.replace("x", "0").replace("X", "0")
    if not s or s == "*":
        return "0.0.0"
    return s


def parse_package_json(path: Path) -> Iterable[tuple[str, str, str, str]]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, ver in (data.get(section) or {}).items():
            yield name, _strip_npm_range(str(ver)), "npm", ""


def parse_package_lock(path: Path) -> Iterable[tuple[str, str, str, str]]:
    """Lockfile parser — covers v1/v2/v3 NPM lockfiles."""
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    seen: set[tuple[str, str]] = set()
    # v2/v3: packages map (keys like "node_modules/foo")
    for key, meta in (data.get("packages") or {}).items():
        if not key:
            continue
        # Strip "node_modules/" prefix; nested packages become last segment
        name = key.split("node_modules/")[-1] if "node_modules/" in key else key
        if not name or name == "":
            continue
        ver = str(meta.get("version") or "0.0.0")
        lic = str(meta.get("license") or "")
        if isinstance(meta.get("license"), dict):
            lic = str(meta["license"].get("type", ""))
        if (name, ver) in seen:
            continue
        seen.add((name, ver))
        yield name, ver, "npm", lic
    # v1: dependencies map
    def _walk(deps: dict) -> Iterable[tuple[str, str, str, str]]:
        for n, m in (deps or {}).items():
            v = str(m.get("version") or "0.0.0")
            if (n, v) not in seen:
                seen.add((n, v))
                yield n, v, "npm", ""
            yield from _walk(m.get("dependencies") or {})
    yield from _walk(data.get("dependencies") or {})


def parse_requirements_txt(path: Path) -> Iterable[tuple[str, str, str, str]]:
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        # name[extras]==1.2.3 ; name>=1.0,<2.0
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([=<>!~]=?\s*[^;\s]+)?", line)
        if not m:
            continue
        name = m.group(1)
        ver_spec = (m.group(2) or "").strip()
        ver = re.sub(r"^[=<>!~]+\s*", "", ver_spec) if ver_spec else "0.0.0"
        yield name, ver or "0.0.0", "pypi", ""


def parse_pyproject(path: Path) -> Iterable[tuple[str, str, str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    # poetry & PEP-621 dependencies — best-effort regex (no toml dep needed)
    seen: set[tuple[str, str]] = set()
    # PEP-621: dependencies = ["foo>=1.0", ...]
    for block in re.findall(r"dependencies\s*=\s*\[([^\]]*)\]", text, flags=re.S):
        for raw in re.findall(r"\"([^\"]+)\"|\'([^\']+)\'", block):
            spec = raw[0] or raw[1]
            spec = spec.split(";")[0].strip()
            m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([=<>!~]=?\s*[^,\s]+)?", spec)
            if not m:
                continue
            name = m.group(1)
            ver = re.sub(r"^[=<>!~]+\s*", "", m.group(2) or "") or "0.0.0"
            if (name, ver) in seen:
                continue
            seen.add((name, ver))
            yield name, ver, "pypi", ""
    # Poetry: [tool.poetry.dependencies] / [tool.poetry.dev-dependencies]
    for block_match in re.finditer(
        r"\[tool\.poetry(?:\.[a-z\-]+)?\.dependencies\](.*?)(?=\n\[|\Z)", text, flags=re.S
    ):
        for line in block_match.group(1).splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, _, val = line.partition("=")
            name = name.strip()
            val = val.strip()
            if name.lower() == "python":
                continue
            ver = "0.0.0"
            if val.startswith("\""):
                ver = val.strip("\"")
            elif val.startswith("{"):
                m = re.search(r"version\s*=\s*\"([^\"]+)\"", val)
                if m:
                    ver = m.group(1)
            ver = ver.lstrip("^~>=<* ")
            ver = re.split(r"[\s|,<>=]+", ver, maxsplit=1)[0] or "0.0.0"
            if (name, ver) in seen:
                continue
            seen.add((name, ver))
            yield name, ver, "pypi", ""


def parse_pom(path: Path) -> Iterable[tuple[str, str, str, str]]:
    """Best-effort regex parser for Maven dependencies (no lxml dep)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    # Resolve simple ${prop} placeholders from <properties>
    props = dict(re.findall(r"<([\w.\-]+)>([^<>${}]+)</\1>", text))
    for dep in re.findall(r"<dependency>(.*?)</dependency>", text, flags=re.S):
        gid = re.search(r"<groupId>([^<]+)</groupId>", dep)
        aid = re.search(r"<artifactId>([^<]+)</artifactId>", dep)
        ver = re.search(r"<version>([^<]+)</version>", dep)
        if not (gid and aid):
            continue
        v = (ver.group(1) if ver else "0.0.0").strip()
        m = re.match(r"^\$\{([^}]+)\}$", v)
        if m:
            v = props.get(m.group(1), "0.0.0")
        name = f"{gid.group(1).strip()}:{aid.group(1).strip()}"
        yield name, v or "0.0.0", "maven", ""


def parse_gradle(path: Path) -> Iterable[tuple[str, str, str, str]]:
    """Best-effort parser for build.gradle dependencies block."""
    text = path.read_text(encoding="utf-8", errors="replace")
    seen: set[tuple[str, str]] = set()
    # Patterns: implementation 'group:artifact:version'  /  "group:artifact:version"
    for q in ("'", "\""):
        for raw in re.findall(rf"{q}([\w.\-]+:[\w.\-]+:[\w.\-+]+){q}", text):
            parts = raw.split(":")
            if len(parts) < 3:
                continue
            name = f"{parts[0]}:{parts[1]}"
            ver = parts[2]
            if (name, ver) in seen:
                continue
            seen.add((name, ver))
            yield name, ver, "maven", ""


def parse_go_mod(path: Path) -> Iterable[tuple[str, str, str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    in_block = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if in_block or line.startswith("require "):
            parts = line.replace("require ", "").split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                yield parts[0], parts[1].lstrip("v"), "go", ""


def collect_components(repo_dir: Path) -> list[tuple[str, str, str, str]]:
    out: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def _add(items: Iterable[tuple[str, str, str, str]]):
        for name, ver, eco, lic in items:
            key = (name, ver, eco)
            if key in seen:
                continue
            seen.add(key)
            out.append((name, ver, eco, lic))

    # Prefer lockfiles when present (richer metadata)
    if (repo_dir / "package-lock.json").exists():
        try:
            _add(parse_package_lock(repo_dir / "package-lock.json"))
        except Exception as exc:
            print(f"  ! lockfile parse failed: {exc}", file=sys.stderr)
    if (repo_dir / "package.json").exists():
        try:
            _add(parse_package_json(repo_dir / "package.json"))
        except Exception as exc:
            print(f"  ! package.json parse failed: {exc}", file=sys.stderr)
    for fname in ("requirements.txt", "requirements-dev.txt"):
        p = repo_dir / fname
        if p.exists():
            try:
                _add(parse_requirements_txt(p))
            except Exception as exc:
                print(f"  ! {fname} parse failed: {exc}", file=sys.stderr)
    if (repo_dir / "pyproject.toml").exists():
        try:
            _add(parse_pyproject(repo_dir / "pyproject.toml"))
        except Exception as exc:
            print(f"  ! pyproject parse failed: {exc}", file=sys.stderr)
    if (repo_dir / "pom.xml").exists():
        try:
            _add(parse_pom(repo_dir / "pom.xml"))
        except Exception as exc:
            print(f"  ! pom.xml parse failed: {exc}", file=sys.stderr)
    if (repo_dir / "build.gradle").exists():
        try:
            _add(parse_gradle(repo_dir / "build.gradle"))
        except Exception as exc:
            print(f"  ! build.gradle parse failed: {exc}", file=sys.stderr)
    if (repo_dir / "go.mod").exists():
        try:
            _add(parse_go_mod(repo_dir / "go.mod"))
        except Exception as exc:
            print(f"  ! go.mod parse failed: {exc}", file=sys.stderr)
    return out


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
_LAST_ERROR: dict = {}

def http_post(path: str, body: dict, max_retries: int = 5) -> tuple[int, dict]:
    """POST with retry/backoff for 429 + transient errors."""
    backoff = 0.5
    last_code = 0
    last_body: dict = {}
    for attempt in range(max_retries):
        req = urllib.request.Request(
            f"{API}{path}",
            data=json.dumps(body).encode(),
            headers={"X-API-Key": KEY, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                last_body = json.loads(e.read().decode() or "{}")
            except Exception:
                last_body = {"error": str(e)}
            last_code = e.code
            # Retry on 429 (rate limit) and 5xx
            if e.code == 429 or 500 <= e.code < 600:
                time.sleep(backoff)
                backoff = min(backoff * 2, 8)
                continue
            # 4xx other than 429 → permanent, save first instance
            if not _LAST_ERROR:
                _LAST_ERROR.update({"code": e.code, "body": last_body, "request": body})
            return e.code, last_body
        except Exception as e:
            last_code = 0
            last_body = {"error": str(e)}
            time.sleep(backoff)
            backoff = min(backoff * 2, 8)
            continue
    if not _LAST_ERROR:
        _LAST_ERROR.update({"code": last_code, "body": last_body, "request": body})
    return last_code, last_body


def http_get(path: str) -> tuple[int, dict | list]:
    req = urllib.request.Request(
        f"{API}{path}",
        headers={"X-API-Key": KEY},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


# --------------------------------------------------------------------------- #
# Main loop — ingest + verify per tenant
# --------------------------------------------------------------------------- #
def purl_for(name: str, version: str, ecosystem: str) -> str:
    eco_map = {"npm": "npm", "pypi": "pypi", "maven": "maven", "go": "golang"}
    e = eco_map.get(ecosystem, ecosystem)
    if ecosystem == "maven" and ":" in name:
        g, a = name.split(":", 1)
        return f"pkg:maven/{g}/{a}@{version}"
    return f"pkg:{e}/{name}@{version}"


def component_type_for(ecosystem: str) -> str:
    return "library"


def main() -> int:
    results: list[dict] = []
    for slug, repo_name, lang in TENANTS:
        repo_dir = FLEET / repo_name
        print(f"\n=== {slug}  ({repo_name}, {lang}) ===")
        if not repo_dir.is_dir():
            print(f"  ! repo dir missing: {repo_dir}")
            results.append({"slug": slug, "repo": repo_name, "components": 0, "error": "repo missing"})
            continue
        comps = collect_components(repo_dir)
        print(f"  parsed: {len(comps)} components")
        if not comps:
            results.append({"slug": slug, "repo": repo_name, "components": 0, "ingested": 0, "error": "no manifests"})
            continue

        ingested = 0
        failed = 0
        first_fail: dict = {}
        for name, ver, eco, lic in comps:
            body = {
                "org_id": slug,
                "project_name": repo_name,
                "component_name": name,
                "component_version": ver,
                "component_type": component_type_for(eco),
                "ecosystem": eco,
                "license": lic or "",
                "purl": purl_for(name, ver, eco),
            }
            code, resp = http_post("/api/v1/sbom-export/components", body)
            if code in (200, 201):
                ingested += 1
            else:
                failed += 1
                if not first_fail:
                    first_fail = {"code": code, "resp": resp, "req": body}
        print(f"  ingested: {ingested}/{len(comps)}  (failed={failed})")
        if first_fail:
            print(f"  first_fail: HTTP {first_fail['code']}  resp={json.dumps(first_fail['resp'])[:300]}")

        # Verify via real export endpoint
        v_code, v_body = http_get(
            f"/api/v1/sbom-export/cyclonedx?org_id={slug}&project_name={repo_name}"
        )
        verified = (
            len(v_body.get("components", [])) if isinstance(v_body, dict) else 0
        )
        bom_format = v_body.get("bomFormat") if isinstance(v_body, dict) else "?"
        spec_ver = v_body.get("specVersion") if isinstance(v_body, dict) else "?"
        print(f"  verify: {bom_format} {spec_ver} — components in CycloneDX = {verified}")

        results.append(
            {
                "slug": slug,
                "repo": repo_name,
                "language": lang,
                "components_parsed": len(comps),
                "ingested": ingested,
                "failed": failed,
                "verified_in_cyclonedx": verified,
                "bomFormat": bom_format,
                "specVersion": spec_ver,
            }
        )

    out = Path("/tmp/sbom_ingest_results.json")
    out.write_text(json.dumps(results, indent=2))
    print(f"\n[done] results → {out}")
    print(json.dumps({"tenants": len(results), "total_ingested": sum(r.get("ingested", 0) for r in results)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
