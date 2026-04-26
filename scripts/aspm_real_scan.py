#!/usr/bin/env python3
"""Run real SAST scans against the 15-tenant fleet at /tmp/fixops-fleet/
and persist findings into ApplicationSecurityEngine so the ASPM dashboard
(/api/v1/appsec/*) shows real data.

NOT a seeder — the SAST findings are produced by the actual SAST engine
scanning real third-party code (juice-shop, NodeGoat, dvna, vulnado, etc.)
that we have on disk for tenant-onboarding tests. The repos themselves
contain real, classified vulnerabilities.

Usage:
  python3 scripts/aspm_real_scan.py [--org-id default] [--fleet-root /tmp/fixops-fleet]
                                     [--apps juice-shop,NodeGoat,dvna] [--max-files 50]
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("aspm_real_scan")

# Map SAST CWE → ASPM category (only categories the engine accepts).
_CWE_TO_CATEGORY = {
    "CWE-89": "injection",        # SQL injection
    "CWE-78": "injection",        # OS command injection
    "CWE-90": "injection",        # LDAP injection
    "CWE-643": "injection",       # XPath injection
    "CWE-79": "xss",              # XSS
    "CWE-611": "xxe",             # XXE
    "CWE-918": "ssrf",            # SSRF
    "CWE-287": "broken_auth",
    "CWE-306": "broken_auth",
    "CWE-200": "sensitive_exposure",
    "CWE-532": "logging",         # log injection / sensitive in logs
    "CWE-22": "path_traversal",
    "CWE-23": "path_traversal",
    "CWE-502": "deserialization",
    "CWE-327": "crypto",
    "CWE-326": "crypto",
    "CWE-798": "sensitive_exposure",  # hardcoded creds
}


def _category_for(cwe: str, message: str) -> str:
    cwe = (cwe or "").strip().upper()
    if cwe in _CWE_TO_CATEGORY:
        return _CWE_TO_CATEGORY[cwe]
    msg = (message or "").lower()
    for key, cat in [
        ("sql", "injection"), ("xss", "xss"), ("xxe", "xxe"),
        ("ssrf", "ssrf"), ("auth", "broken_auth"), ("password", "sensitive_exposure"),
        ("traversal", "path_traversal"), ("deserial", "deserialization"),
        ("crypto", "crypto"), ("md5", "crypto"), ("sha1", "crypto"),
    ]:
        if key in msg:
            return cat
    return "injection"


def _language_for(path: str) -> str:
    p = path.lower()
    if p.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
        return "javascript"
    if p.endswith(".py"):
        return "python"
    if p.endswith(".java"):
        return "java"
    if p.endswith(".go"):
        return "go"
    if p.endswith((".rb", ".erb")):
        return "ruby"
    return "other"


def main(argv: List[str] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--org-id", default="default")
    p.add_argument("--fleet-root", default="/tmp/fixops-fleet")
    p.add_argument(
        "--apps",
        default="juice-shop,NodeGoat,dvna,vulnado,WebGoat,django,flask,express",
        help="Comma-separated subdir names under fleet-root",
    )
    p.add_argument("--max-files", type=int, default=80)
    args = p.parse_args(argv)

    _REPO_ROOT = "/Users/devops.ai/fixops/Fixops"
    for sub in ("", "suite-core", "suite-core/core", "suite-api", "suite-attack",
                "suite-feeds", "suite-evidence-risk", "suite-integrations"):
        path = os.path.join(_REPO_ROOT, sub) if sub else _REPO_ROOT
        if path not in sys.path:
            sys.path.insert(0, path)
    try:
        import sitecustomize  # noqa: F401
    except Exception:
        pass

    from core.application_security_engine import ApplicationSecurityEngine
    from core.sast_engine import SASTEngine, EXT_TO_LANG  # type: ignore

    fleet_root = Path(args.fleet_root)
    if not fleet_root.exists():
        log.error("Fleet root not found: %s", fleet_root)
        return 1

    asp = ApplicationSecurityEngine(org_id=args.org_id)
    sast = SASTEngine()
    apps_to_scan = [a.strip() for a in args.apps.split(",") if a.strip()]
    summary: Dict[str, Any] = {"org_id": args.org_id, "apps": []}

    for app_name in apps_to_scan:
        app_dir = fleet_root / app_name
        if not app_dir.exists() or not app_dir.is_dir():
            log.warning("Skip %s — not present at %s", app_name, app_dir)
            continue

        # Pick a primary language by counting matching files.
        lang_counts: Dict[str, int] = {}
        targets = []
        for fp in app_dir.rglob("*"):
            if not fp.is_file():
                continue
            if fp.suffix.lower() not in EXT_TO_LANG:
                continue
            lang_counts[_language_for(str(fp))] = (
                lang_counts.get(_language_for(str(fp)), 0) + 1
            )
            targets.append(str(fp))
            if len(targets) >= args.max_files:
                break
        if not targets:
            log.warning("Skip %s — no scannable files", app_name)
            continue

        primary_lang = max(lang_counts.items(), key=lambda kv: kv[1])[0]
        log.info("Scanning %s (%d files, lang=%s)…", app_name, len(targets), primary_lang)

        # Register or reuse the application
        app_record = None
        for ex in asp.list_apps(args.org_id):
            if ex.get("name") == app_name:
                app_record = ex
                break
        if app_record is None:
            try:
                app_record = asp.register_app(
                    args.org_id,
                    {
                        "name": app_name,
                        "app_type": "web",
                        "language": primary_lang if primary_lang in {
                            "javascript", "python", "java", "go", "ruby",
                            "csharp", "php", "other",
                        } else "other",
                        "repo_url": f"https://github.com/{app_name}",
                        "owner_team": "security",
                        "criticality": "high",
                    },
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("register_app(%s) failed: %s", app_name, exc)
                continue

        app_id = app_record["id"]

        # Real SAST scan
        try:
            scan_result = sast.scan_path(str(app_dir), file_list=targets)
        except Exception as exc:  # noqa: BLE001
            log.warning("SAST scan failed for %s: %s", app_name, exc)
            continue

        # Persist real findings
        ingested = 0
        for f in (scan_result.findings or [])[:200]:
            d = f.to_dict()
            try:
                asp.add_sast_finding(
                    args.org_id,
                    app_id,
                    {
                        "tool": "semgrep",
                        "rule_id": d.get("rule_id", "")[:64],
                        "title": (d.get("title") or d.get("message") or "SAST finding")[:255],
                        "category": _category_for(d.get("cwe_id", ""), d.get("message", "")),
                        "severity": d.get("severity", "medium"),
                        "file_path": d.get("file_path", "")[:512],
                        "line_number": d.get("line_number", 0),
                        "code_snippet": d.get("snippet", "")[:1000],
                        "cwe_id": d.get("cwe_id", "")[:32],
                    },
                )
                ingested += 1
            except Exception as exc:  # noqa: BLE001
                log.debug("add_sast_finding failed: %s", exc)

        # Log a scan run
        try:
            from core.application_security_engine import _now_iso  # type: ignore
            asp.log_scan_run(
                args.org_id,
                app_id,
                {
                    "scan_type": "sast",
                    "tool": "semgrep",
                    "status": "completed",
                    "findings_count": ingested,
                    "started_at": _now_iso(),
                    "completed_at": _now_iso(),
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("log_scan_run failed: %s", exc)

        summary["apps"].append(
            {"name": app_name, "id": app_id, "files": len(targets), "findings": ingested}
        )
        log.info("  → %s: %d findings persisted", app_name, ingested)

    # Final stats
    try:
        stats = asp.get_stats(args.org_id)
        summary["stats"] = stats
        log.info("ASPM stats for org=%s: %s", args.org_id, stats)
    except Exception as exc:  # noqa: BLE001
        log.warning("get_stats failed: %s", exc)

    import json
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
