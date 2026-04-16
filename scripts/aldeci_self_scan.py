#!/usr/bin/env python3
"""
ALDECI Self-Scan — the platform eating its own dog food.
Scans the Fixops repo through ALDECI's own engines and prints a full security assessment.

Steps:
  1. Register ALDECI as an application asset (brain/ingest/asset)
  2. Upload pre-existing Bandit, Semgrep, Trivy scan results via scanner-ingest webhook
  3. Check for self-scan endpoint; trigger brain pipeline run
  4. Query ALDECI's engines: findings, risk, SBOM, compliance, stats, scoreboard, remediation
  5. Print ALDECI Self-Assessment Report
"""

import json
import time
import sys
from datetime import datetime
from pathlib import Path

import urllib.request
import urllib.error

BASE_URL = "http://localhost:8000"
API_KEY  = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
DELAY    = 0.7

BANDIT_JSON  = "/tmp/bandit_fixops.json"
SEMGREP_JSON = "/tmp/semgrep_fixops.json"
TRIVY_JSON   = "/tmp/trivy_fixops.json"

HEADERS = {
    "X-API-Key":    API_KEY,
    "Content-Type": "application/json",
    "X-Org-ID":     "fixops-prod",
}

# ANSI colours
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; X = "\033[0m"


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _req(method: str, path: str, body=None) -> dict:
    url  = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            try:
                return {"ok": True, "status": resp.status, "data": json.loads(raw)}
            except json.JSONDecodeError:
                return {"ok": True, "status": resp.status, "data": raw}
    except urllib.error.HTTPError as e:
        body_txt = ""
        try:
            body_txt = e.read().decode()[:400]
        except Exception:
            pass
        return {"ok": False, "status": e.code, "error": body_txt}
    except Exception as exc:
        return {"ok": False, "status": 0, "error": str(exc)}


def get(path: str) -> dict:
    r = _req("GET", path)
    time.sleep(DELAY)
    return r


def post(path: str, body: dict) -> dict:
    r = _req("POST", path, body)
    time.sleep(DELAY)
    return r


def tick(ok: bool) -> str:
    return f"{G}✓{X}" if ok else f"{R}✗{X}"


def section(title: str) -> None:
    print(f"\n{B}{'═'*72}{X}")
    print(f"{B}  {title}{X}")
    print(f"{B}{'═'*72}{X}")


# ── Step 1: Register ALDECI as an application asset ───────────────────────────

def step1_register_asset() -> dict:
    section("STEP 1 — Register ALDECI as Application Asset")
    payload = {
        "asset_id": "aldeci-platform",
        "name":     "ALDECI Security Platform",
        "type":     "application",
        "metadata": {
            "repo":      "DevOpsMadDog/Fixops",
            "language":  "Python",
            "framework": "FastAPI",
        },
    }
    r = post("/api/v1/brain/ingest/asset", payload)
    d = r.get("data", {})
    node_id = d.get("node_id", d.get("id", "n/a")) if isinstance(d, dict) else "n/a"
    message = d.get("message", d.get("status", "ingested")) if isinstance(d, dict) else str(d)[:80]
    print(f"  {tick(r['ok'])} POST /api/v1/brain/ingest/asset  HTTP {r.get('status')}")
    if r["ok"]:
        print(f"       node_id : {node_id}")
        print(f"       message : {message}")
    else:
        print(f"       error   : {r.get('error','')[:200]}")
    return r


# ── Step 2: Upload scanner results ────────────────────────────────────────────

def step2_upload_scanners() -> dict:
    section("STEP 2 — Upload Pre-existing Scan Results via Scanner-Ingest Webhook")
    results = {}
    for scanner, fpath in [
        ("bandit",  BANDIT_JSON),
        ("semgrep", SEMGREP_JSON),
        ("trivy",   TRIVY_JSON),
    ]:
        p = Path(fpath)
        if not p.exists():
            print(f"  {Y}⚠{X}  [{scanner:8s}] SKIP — file not found: {fpath}")
            results[scanner] = None
            continue
        payload = json.loads(p.read_text())
        r       = post(f"/api/v1/scanner-ingest/webhook/{scanner}", payload)
        d       = r.get("data", {})
        count   = d.get("findings_count", d.get("total_findings", "?")) if isinstance(d, dict) else "?"
        ms      = d.get("parse_time_ms", "?") if isinstance(d, dict) else "?"
        print(f"  {tick(r['ok'])} [{scanner:8s}] HTTP {r.get('status'):3}  "
              f"findings_ingested={count}  parse_ms={ms}")
        if not r["ok"]:
            print(f"             error: {r.get('error','')[:160]}")
        results[scanner] = r
    return results


# ── Step 3: Self-scan endpoint + brain pipeline ────────────────────────────────

def step3_self_scan() -> dict:
    section("STEP 3 — Self-Scan Endpoint Check + Brain Pipeline")

    for path in ["/api/v1/self-scan/", "/api/v1/self-scan/run"]:
        r = get(path)
        marker = tick(r["ok"])
        print(f"  {marker} GET {path}  -> HTTP {r.get('status', 0)}")
        if r["ok"]:
            print(f"       {json.dumps(r['data'])[:120]}")

    print(f"\n  Triggering Brain Pipeline (ALDECI analysing itself)...")
    r = post("/api/v1/brain/pipeline/run", {
        "target": "aldeci-platform",
        "mode":   "full",
        "org_id": "fixops-prod",
    })
    d = r.get("data", {}) if isinstance(r.get("data"), dict) else {}
    print(f"  {tick(r['ok'])} POST /api/v1/brain/pipeline/run  HTTP {r.get('status')}")
    if r["ok"]:
        print(f"       run_id : {d.get('run_id', 'n/a')}")
        print(f"       status : {d.get('status', 'n/a')}")
    else:
        print(f"       note   : {r.get('error','')[:160]}")
    return r


# ── Step 4: Query ALDECI's engines ────────────────────────────────────────────

def step4_query_engines() -> dict:
    section("STEP 4 — Querying ALDECI Engines About Itself")
    results = {}

    # 4a — findings
    print(f"\n  {C}[4a]{X} GET /api/v1/findings")
    r = get("/api/v1/findings?limit=200&org_id=fixops-prod")
    results["findings"] = r
    if r["ok"]:
        d = r["data"]
        print(f"       total={d.get('total', 0)}  returned={len(d.get('findings', []))}")
    else:
        print(f"       error: {r.get('error','')[:120]}")

    # 4b — risk overview
    print(f"\n  {C}[4b]{X} GET /api/v1/risk/overview")
    r = get("/api/v1/risk/overview?org_id=fixops-prod")
    results["risk"] = r
    if r["ok"]:
        d   = r["data"]
        sev = d.get("severity_breakdown", {})
        print(f"       risk_score={d.get('risk_score','n/a')}  risk_level={d.get('risk_level','n/a')}")
        print(f"       total_findings={d.get('total_findings',0)}  total_components={d.get('total_components',0)}")
        print(f"       severity: critical={sev.get('critical',0)} high={sev.get('high',0)} "
              f"medium={sev.get('medium',0)} low={sev.get('low',0)}")
    else:
        print(f"       error: {r.get('error','')[:120]}")

    # 4c — SBOM generate then licenses
    print(f"\n  {C}[4c]{X} POST /api/v1/sbom/generate  (ALDECI scanning its own dependencies)")
    r_gen = post("/api/v1/sbom/generate", {
        "project_path": "/Users/devops.ai/fixops/Fixops",
        "project_name": "ALDECI",
        "org_id":       "fixops-prod",
    })
    results["sbom_generate"] = r_gen
    if r_gen["ok"]:
        d    = r_gen["data"]
        sbom = d.get("sbom", d) if isinstance(d, dict) else {}
        comps = sbom.get("components", []) if isinstance(sbom, dict) else []
        print(f"       format={d.get('format','n/a')}  components={len(comps)}")
    else:
        print(f"       error: {r_gen.get('error','')[:120]}")

    print(f"\n       GET /api/v1/sbom/licenses")
    r = get("/api/v1/sbom/licenses?org_id=fixops-prod")
    results["sbom_licenses"] = r
    if r["ok"]:
        d = r["data"]
        print(f"       total={d.get('total',0)}  high_risk_count={d.get('high_risk_count',0)}  "
              f"distinct_licenses={len(d.get('licenses',[]))}")
    else:
        print(f"       error: {r.get('error','')[:120]}")

    # 4d — compliance status
    print(f"\n  {C}[4d]{X} GET /api/v1/compliance/status")
    r = get("/api/v1/compliance/status?org_id=fixops-prod")
    results["compliance"] = r
    if r["ok"]:
        d = r["data"]
        print(f"       status={d.get('status','n/a')}  overall_score={d.get('overall_score','n/a')}")
        for fw in d.get("frameworks", []):
            print(f"         {fw.get('id','?'):12s}  score={fw.get('score','?'):5}  "
                  f"controls={fw.get('controls_met',0)}/{fw.get('controls_total',0)}")
    else:
        print(f"       error: {r.get('error','')[:120]}")

    # 4e — scanner-ingest stats
    print(f"\n  {C}[4e]{X} GET /api/v1/scanner-ingest/stats")
    r = get("/api/v1/scanner-ingest/stats")
    results["ingest_stats"] = r
    if r["ok"]:
        d = r["data"]
        print(f"       total_findings_ingested={d.get('total_findings_ingested',0)}  "
              f"distinct_scanners={d.get('distinct_scanners',0)}")
        for src, info in d.get("by_source", {}).items():
            print(f"         {src:18s}  findings={info.get('findings',0)}")
        sess = d.get("in_session", {})
        print(f"       this-session: files={sess.get('files_processed',0)}  "
              f"findings={sess.get('findings_parsed',0)}  errors={sess.get('errors',0)}")
    else:
        print(f"       error: {r.get('error','')[:120]}")

    # 4f — security scoreboard
    print(f"\n  {C}[4f]{X} GET /api/v1/security-scoreboard/leaderboard?org_id=fixops-prod")
    r = get("/api/v1/security-scoreboard/leaderboard?org_id=fixops-prod")
    results["scoreboard"] = r
    if r["ok"]:
        d       = r["data"]
        entries = d if isinstance(d, list) else d.get("leaderboard", d.get("entries", []))
        count   = len(entries) if isinstance(entries, list) else "n/a"
        print(f"       leaderboard entries: {count}")
        if isinstance(entries, list):
            for e in entries[:5]:
                print(f"         {e.get('team', e.get('name','?')):25s}  "
                      f"score={e.get('score','?')}")
    else:
        print(f"       HTTP {r.get('status')}  {r.get('error','')[:120]}")

    # 4g — remediation statuses
    print(f"\n  {C}[4g]{X} GET /api/v1/remediation/statuses")
    r = get("/api/v1/remediation/statuses?org_id=fixops-prod")
    results["remediation"] = r
    if r["ok"]:
        d       = r["data"]
        statuses = d.get("statuses", d if isinstance(d, list) else [])
        print(f"       available statuses: {statuses}")
    else:
        print(f"       error: {r.get('error','')[:120]}")

    # 4h — brain stats
    print(f"\n  {C}[4h]{X} GET /api/v1/brain/stats  (Knowledge Graph)")
    r = get("/api/v1/brain/stats?org_id=fixops-prod")
    results["brain_stats"] = r
    if r["ok"]:
        d = r["data"]
        print(f"       total_nodes={d.get('total_nodes',0)}  total_edges={d.get('total_edges',0)}")
        print(f"       total_findings={d.get('total_findings',0)}  total_assets={d.get('total_assets',0)}")
    else:
        print(f"       error: {r.get('error','')[:120]}")

    return results


# ── Step 5: ALDECI Self-Assessment Report ─────────────────────────────────────

def step5_report(scanner_results: dict, engine_results: dict) -> None:
    section("STEP 5 — ALDECI SELF-ASSESSMENT REPORT")

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n  Generated : {now}")
    print(f"  Target    : ALDECI Security Platform (DevOpsMadDog/Fixops)")
    print(f"  Scanned by: ALDECI itself (dog-food mode)\n")

    # ── Parse raw scan files ───────────────────────────────────────────────────
    file_findings: dict[str, list] = {}
    print("  ┌─ Scanner Input Files ─────────────────────────────────────────────┐")
    for scanner, fpath in [("bandit", BANDIT_JSON), ("semgrep", SEMGREP_JSON), ("trivy", TRIVY_JSON)]:
        p = Path(fpath)
        if p.exists():
            raw  = json.loads(p.read_text())
            items = raw.get("results") or raw.get("Results") or []
            if scanner == "trivy":
                vulns: list = []
                for tgt in items:
                    vulns.extend(tgt.get("Vulnerabilities") or [])
                items = vulns
            file_findings[scanner] = items
            print(f"  │  {scanner:8s}  {len(items):4d} raw findings  ({fpath})")
        else:
            file_findings[scanner] = []
            print(f"  │  {scanner:8s}  file not found ({fpath})")
    print("  └────────────────────────────────────────────────────────────────────┘\n")

    # ── Severity tally ─────────────────────────────────────────────────────────
    sev_counts: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "ERROR": 0,
        "MEDIUM": 0, "WARNING": 0, "LOW": 0, "INFO": 0, "OTHER": 0,
    }
    all_findings: list[dict] = []

    for f in file_findings.get("bandit", []):
        sev = f.get("issue_severity", "OTHER").upper()
        sev_counts[sev if sev in sev_counts else "OTHER"] += 1
        all_findings.append({
            "source":   "Bandit",
            "severity": sev,
            "title":    f.get("issue_text", "")[:80],
            "file":     f.get("filename", "")[:65],
            "line":     f.get("line_number", "?"),
            "cwe":      f.get("issue_cwe", {}).get("id", ""),
            "confidence": f.get("issue_confidence", ""),
        })

    for f in file_findings.get("semgrep", []):
        extra = f.get("extra", {})
        meta  = extra.get("metadata", {})
        sev   = (extra.get("severity") or meta.get("severity") or "MEDIUM").upper()
        sev_counts[sev if sev in sev_counts else "OTHER"] += 1
        all_findings.append({
            "source":   "Semgrep",
            "severity": sev,
            "title":    (extra.get("message") or f.get("check_id", ""))[:80],
            "file":     f.get("path", "")[:65],
            "line":     f.get("start", {}).get("line", "?"),
            "cwe":      f.get("check_id", ""),
            "confidence": "",
        })

    for f in file_findings.get("trivy", []):
        sev = f.get("Severity", "UNKNOWN").upper()
        sev_counts[sev if sev in sev_counts else "OTHER"] += 1
        all_findings.append({
            "source":   "Trivy",
            "severity": sev,
            "title":    (f"{f.get('VulnerabilityID','?')} in {f.get('PkgName','?')} "
                         f"{f.get('InstalledVersion','')}").strip()[:80],
            "file":     f.get("PkgName", "")[:65],
            "line":     f.get("VulnerabilityID", "?"),
            "cwe":      f.get("VulnerabilityID", ""),
            "confidence": f.get("FixedVersion", ""),
        })

    total_raw = sum(sev_counts.values())

    # ── 5a: Findings by severity ───────────────────────────────────────────────
    print("  ┌─ 1. Total Findings by Severity (raw scan files) ──────────────────┐")
    display_order = ["CRITICAL", "HIGH", "ERROR", "MEDIUM", "WARNING", "LOW", "INFO", "OTHER"]
    for sev in display_order:
        cnt = sev_counts[sev]
        if cnt == 0:
            continue
        bar = "█" * min(cnt, 48)
        col = R if sev in ("CRITICAL", "HIGH", "ERROR") else (
              Y if sev in ("MEDIUM", "WARNING") else G)
        print(f"  │  {col}{sev:8s}{X}  {cnt:4d}  {col}{bar}{X}")
    print(f"  │  {'TOTAL':8s}  {total_raw:4d}")
    print("  └────────────────────────────────────────────────────────────────────┘\n")

    # ── 5b: SBOM component count & licenses ───────────────────────────────────
    print("  ┌─ 2. SBOM Component Count & License Distribution ───────────────────┐")
    r_gen  = engine_results.get("sbom_generate", {})
    r_lic  = engine_results.get("sbom_licenses", {})
    if r_gen.get("ok"):
        d    = r_gen["data"]
        sbom = d.get("sbom", d) if isinstance(d, dict) else {}
        comps = sbom.get("components", []) if isinstance(sbom, dict) else []
        print(f"  │  Component count  : {len(comps)}")
        # Collect licenses from component properties (ALDECI's generator stores them there)
        lic_map: dict[str, int] = {}
        for c in comps:
            for prop in c.get("properties", []):
                if isinstance(prop, dict) and "licens" in prop.get("name", "").lower():
                    val = prop.get("value", "unknown")
                    lic_map[val] = lic_map.get(val, 0) + 1
            for lic in c.get("licenses", []):
                if isinstance(lic, dict):
                    name = lic.get("license", {}).get("id") or lic.get("expression", "unknown")
                else:
                    name = str(lic)
                lic_map[name] = lic_map.get(name, 0) + 1
        if lic_map:
            print(f"  │  License distribution ({len(lic_map)} distinct):")
            for lic, cnt in sorted(lic_map.items(), key=lambda x: -x[1])[:10]:
                print(f"  │    {lic:32s}  {cnt}")
        else:
            # Show sample component list
            print(f"  │  Sample components:")
            for c in comps[:8]:
                print(f"  │    {c.get('name','?'):30s}  {c.get('version','?')}")
    else:
        print("  │  SBOM generate not available or failed")

    if r_lic.get("ok"):
        d = r_lic["data"]
        print(f"  │  SBOM license endpoint: total={d.get('total',0)}  "
              f"high_risk={d.get('high_risk_count',0)}")
        for lic in d.get("licenses", [])[:5]:
            print(f"  │    {lic.get('name','?'):30s}  risk={lic.get('risk_level','?')}")
    print("  └────────────────────────────────────────────────────────────────────┘\n")

    # ── 5c: Compliance status ──────────────────────────────────────────────────
    print("  ┌─ 3. Compliance Status ─────────────────────────────────────────────┐")
    r_comp = engine_results.get("compliance", {})
    if r_comp.get("ok"):
        d = r_comp["data"]
        print(f"  │  Overall score : {d.get('overall_score','n/a')}%")
        print(f"  │  Method        : {d.get('scoring_method','n/a')}")
        if d.get("scoring_note"):
            print(f"  │  Note          : {d['scoring_note'][:80]}")
        for fw in d.get("frameworks", []):
            sc   = fw.get("score", 0)
            icon = f"{G}✓{X}" if sc >= 80 else f"{Y}⚠{X}"
            print(f"  │  {icon} {fw.get('name','?'):35s}  {sc:5}%  "
                  f"controls={fw.get('controls_met',0)}/{fw.get('controls_total',0)}")
    else:
        print("  │  Not available")
    print("  └────────────────────────────────────────────────────────────────────┘\n")

    # ── 5d: Risk overview ─────────────────────────────────────────────────────
    print("  ┌─ 4. Risk Overview ─────────────────────────────────────────────────┐")
    r_risk = engine_results.get("risk", {})
    if r_risk.get("ok"):
        d     = r_risk["data"]
        score = d.get("risk_score", 0)
        level = d.get("risk_level", "unknown")
        sev   = d.get("severity_breakdown", {})
        trend = d.get("trends", {})
        icon  = {"critical": f"{R}CRITICAL{X}", "high": f"{R}HIGH{X}",
                 "medium": f"{Y}MEDIUM{X}", "low": f"{G}LOW{X}"}.get(level, level.upper())
        print(f"  │  Risk score : {score}   Risk level : {icon}")
        print(f"  │  Findings   : {d.get('total_findings',0)} total  "
              f"Components: {d.get('total_components',0)}")
        print(f"  │  Breakdown  : critical={sev.get('critical',0)}  high={sev.get('high',0)}  "
              f"medium={sev.get('medium',0)}  low={sev.get('low',0)}")
        print(f"  │  Trend      : {trend.get('direction','stable')}  "
              f"(7d: {trend.get('change_7d',0):+}  30d: {trend.get('change_30d',0):+})")
        for tr in d.get("top_risks", [])[:3]:
            print(f"  │  Top risk   : {str(tr)[:80]}")
    else:
        print("  │  Not available")
    print("  └────────────────────────────────────────────────────────────────────┘\n")

    # ── 5e: Top 10 most critical findings ─────────────────────────────────────
    print("  ┌─ 5. Top 10 Most Critical Findings ────────────────────────────────┐")
    sev_rank = {"CRITICAL": 0, "ERROR": 1, "HIGH": 1, "WARNING": 2, "MEDIUM": 2,
                "LOW": 3, "INFO": 4, "OTHER": 5, "UNKNOWN": 5}
    ranked = sorted(all_findings, key=lambda f: sev_rank.get(f["severity"], 5))
    if ranked:
        for i, f in enumerate(ranked[:10], 1):
            sev   = f["severity"]
            scol  = R if sev in ("CRITICAL","HIGH","ERROR") else (Y if sev in ("MEDIUM","WARNING") else G)
            src   = f["source"]
            title = f["title"]
            print(f"  │  #{i:2d} {scol}[{sev:8s}]{X} {src:7s}  {title[:60]}")
            extra = f["confidence"]
            if extra:
                print(f"  │       fix/confidence: {str(extra)[:60]}  file: {f['file'][:45]}  line:{f['line']}")
            else:
                print(f"  │       file: {f['file'][:55]}  line:{f['line']}")
    else:
        print("  │  No findings parsed from raw scan files")
    print("  └────────────────────────────────────────────────────────────────────┘\n")

    # ── 5f: Ingestion statistics ──────────────────────────────────────────────
    print("  ┌─ 6. Ingestion Statistics ──────────────────────────────────────────┐")
    r_stats = engine_results.get("ingest_stats", {})
    if r_stats.get("ok"):
        d    = r_stats["data"]
        sess = d.get("in_session", {})
        print(f"  │  Total ever ingested : {d.get('total_findings_ingested',0)}")
        print(f"  │  Distinct sources    : {d.get('distinct_scanners',0)}")
        print(f"  │  Last ingest at      : {d.get('last_ingest_at','never')}")
        print(f"  │  Breakdown by source :")
        for src, info in d.get("by_source", {}).items():
            print(f"  │    {src:20s}  {info.get('findings',0)} findings")
        print(f"  │  This-session counters: "
              f"files={sess.get('files_processed',0)}  "
              f"findings={sess.get('findings_parsed',0)}  "
              f"errors={sess.get('errors',0)}")
    else:
        print("  │  Not available")
    print("  └────────────────────────────────────────────────────────────────────┘\n")

    # ── 5g: Knowledge Brain stats ─────────────────────────────────────────────
    r_brain = engine_results.get("brain_stats", {})
    if r_brain.get("ok"):
        d = r_brain["data"]
        print("  ┌─ 7. Knowledge Brain (Graph DB) ────────────────────────────────────┐")
        print(f"  │  Nodes    : {d.get('total_nodes',0)}")
        print(f"  │  Edges    : {d.get('total_edges',0)}")
        print(f"  │  Assets   : {d.get('total_assets',0)}")
        print(f"  │  Findings : {d.get('total_findings',0)}")
        print("  └────────────────────────────────────────────────────────────────────┘\n")

    # ── 5h: Verdict ───────────────────────────────────────────────────────────
    critical = sev_counts["CRITICAL"]
    high     = sev_counts["HIGH"] + sev_counts["ERROR"]
    medium   = sev_counts["MEDIUM"] + sev_counts["WARNING"]
    low      = sev_counts["LOW"] + sev_counts["INFO"] + sev_counts["OTHER"]

    if critical > 0:
        verdict = f"{R}CRITICAL — Immediate remediation required{X}"
    elif high > 20:
        verdict = f"{R}HIGH RISK — Prioritised remediation needed{X}"
    elif high > 0:
        verdict = f"{Y}MODERATE RISK — Schedule remediation sprint{X}"
    else:
        verdict = f"{G}LOW RISK — Maintain security hygiene{X}"

    active_scanners = sum(1 for v in scanner_results.values() if v and v.get("ok"))

    print("  ┌─ ASSESSMENT VERDICT ───────────────────────────────────────────────┐")
    print(f"  │  Verdict   : {verdict}")
    print(f"  │  Critical  : {critical}   High: {high}   Medium: {medium}   Low/Info: {low}")
    print(f"  │  Raw total : {total_raw} findings across {active_scanners} scanners ingested")
    print("  └────────────────────────────────────────────────────────────────────┘")
    print()


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{B}{C}{'╔'+'═'*72+'╗'}{X}")
    print(f"{B}{C}║{'ALDECI SELF-SCAN  —  Platform Eating Its Own Dog Food':^72}║{X}")
    print(f"{B}{C}║{'Target: DevOpsMadDog/Fixops  |  Backend: localhost:8000':^72}║{X}")
    print(f"{B}{C}{'╚'+'═'*72+'╝'}{X}\n")

    # Verify backend is alive
    health = get("/api/v1/scanner-ingest/health")
    if not health.get("ok"):
        health = get("/api/v1/brain/health")
    status_word = f"{G}OK{X}" if health.get("ok") else f"{Y}WARN (continuing anyway){X}"
    print(f"  Backend health check: HTTP {health.get('status','?')}  {status_word}\n")

    step1_register_asset()
    scanner_results  = step2_upload_scanners()
    step3_self_scan()
    engine_results   = step4_query_engines()
    step5_report(scanner_results, engine_results)

    print(f"  {G}Self-scan complete.{X}\n")


if __name__ == "__main__":
    main()
