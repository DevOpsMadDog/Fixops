"""Closed-Loop Decision Router — ALDECI (SPEC-016 increment 3).

Prefix: /api/v1/closed-loop

Takes an ingested finding, renders an air-gapped council verdict, and (on block/defer)
writes the decision back into the customer's systems of record — Jira ticket + ServiceNow
incident + Splunk event — then signs the decision bundle and appends it to the immutable
evidence chain. This is the "close the loop" half of stack-fit: ALDECI's correlated
verdict flows back into the tools the SCIF org already operates.

Debate-hardened (SCIF-Accreditor + Red-Team):
  REQ-016-08  finding lookup is org-scoped (get_finding(id, org_id)) -> 404 on miss;
              all finding text escaped before external ticket writes (no mention/script injection).
  REQ-016-09  deliveries deduped on (org_id, finding_id, verdict_hash) via UNIQUE constraint;
              replay returns the stored receipt, never re-writes Jira/ServiceNow.
  REQ-016-10  the ML-DSA-signed decision bundle (subject + org + classification + full I/O +
              monotonic ts) is appended to the tamper-evident evidence_chain — AU-2/3/9/12;
              the HTTP signature alone is not the system of record.
  REQ-016-07  every outbound target URL passes the egress/SSRF guard before any socket opens.

NO MOCKS: unconfigured targets return honest per-target receipts (delivered/not_configured/failed).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/closed-loop", tags=["Closed-Loop Decision"],
                   dependencies=[Depends(api_key_auth)])

_DB_PATH = Path(os.environ.get("FIXOPS_CLOSED_LOOP_DB", "data/closed_loop.db"))


# ---------------------------------------------------------------------------
# Dedup / receipt store (REQ-016-09)
# ---------------------------------------------------------------------------


def _conn() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(_DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute(
        """CREATE TABLE IF NOT EXISTS closed_loop_deliveries (
            org_id        TEXT NOT NULL,
            finding_id    TEXT NOT NULL,
            verdict_hash  TEXT NOT NULL,
            decision      TEXT NOT NULL,
            receipts      TEXT NOT NULL,
            evidence_seq  INTEGER,
            evidence_sig  TEXT,
            created_at    REAL NOT NULL,
            PRIMARY KEY (org_id, finding_id, verdict_hash)
        )"""
    )
    return con


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe(text: Any, limit: int = 500) -> str:
    """Escape finding text before it is written to an external ticket (REQ-016-08).

    Strips control chars + the Jira ``[~user]`` mention primitive + leading sigils that
    trigger ServiceNow business rules / markup, and bounds length.
    """
    s = "" if text is None else str(text)
    s = s.replace("[~", "[ ~").replace("</", "< /").replace("<script", "&lt;script")
    s = "".join(ch for ch in s if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    s = s.lstrip("=+@-\t ")  # neutralise formula/markup-injection leading sigils
    return s[:limit]


def _decision_from_action(action: str) -> str:
    a = (action or "").lower()
    if a.startswith("remediate") or a in ("block", "escalate"):
        return "block"
    if a in ("defer", "investigate"):
        return "defer"
    return "allow"  # accept_risk, false_positive, allow


def _render_verdict(finding: Dict[str, Any], org_id: str) -> Dict[str, Any]:
    """Council verdict with honest fallback labelling (no fake AI)."""
    context = {
        "service_name": finding.get("asset_name") or finding.get("asset_id") or "unknown",
        "risk_score": finding.get("cvss_score") or finding.get("risk_score"),
    }
    try:
        from core.llm_council import CouncilFactory

        # CouncilFactory.create_default_council is an INSTANCE method returning an
        # LLMCouncilEngine whose convene() is synchronous. Must instantiate the factory.
        council = CouncilFactory().create_default_council()
        verdict = council.convene(finding, context, org_id)
        return {
            "action": verdict.action,
            "confidence": getattr(verdict, "confidence", None),
            "reasoning": _safe(getattr(verdict, "reasoning", ""), 2000),
            "verdict_source": "council",
        }
    except Exception as exc:  # noqa: BLE001 - council unconfigured/air-gapped w/o local LLM
        _logger.info("closed-loop: council unavailable (%s) -> severity fallback",
                     type(exc).__name__)
        sev = (finding.get("severity") or "medium").lower()
        action = ("remediate_critical" if sev in ("critical", "high")
                  else "defer" if sev == "medium" else "accept_risk")
        return {
            "action": action,
            "confidence": None,
            "reasoning": f"severity-based fallback (council unavailable): severity={sev}",
            "verdict_source": "severity_fallback",
        }


def _egress_ok(url: Optional[str], name: str) -> Optional[str]:
    """Return None if egress allowed, else a 'not_configured'/'blocked' reason string."""
    from core.airgap_config import assert_egress_allowed, EgressBlocked

    try:
        assert_egress_allowed(url, name)
        return None
    except EgressBlocked as exc:
        return str(exc)


def _deliver_jira(finding: Dict[str, Any], verdict: Dict[str, Any]) -> Dict[str, Any]:
    from core.connectors import JiraConnector

    conn = JiraConnector({
        "url": os.environ.get("JIRA_URL") or os.environ.get("ALDECI_JIRA_URL"),
        "project_key": os.environ.get("JIRA_PROJECT_KEY"),
        "user_email": os.environ.get("JIRA_USER_EMAIL") or os.environ.get("JIRA_USER"),
        "token_env": "JIRA_TOKEN",
    })
    if not conn.configured:
        return {"target": "jira", "status": "not_configured"}
    blocked = _egress_ok(conn.base_url, "jira")
    if blocked:
        return {"target": "jira", "status": "blocked", "detail": blocked}
    out = conn.create_issue({
        "summary": _safe(f"[ALDECI {verdict['action']}] {finding.get('title')}", 240),
        "description": _safe(
            f"Finding: {finding.get('id')}\nSeverity: {finding.get('severity')}\n"
            f"CVE: {finding.get('cve_id')}\nVerdict: {verdict['action']} "
            f"(source={verdict['verdict_source']})\n\n{verdict['reasoning']}", 2000),
        "priority": "High" if verdict["action"].startswith("remediate") else "Medium",
    })
    status = "delivered" if out.status not in ("skipped", "failed") else (
        "not_configured" if out.status == "skipped" else "failed")
    ref = (out.details or {}).get("key") or (out.details or {}).get("id")
    return {"target": "jira", "status": status, "ref": ref}


def _deliver_servicenow(finding: Dict[str, Any], verdict: Dict[str, Any]) -> Dict[str, Any]:
    from core.connectors import ServiceNowConnector

    conn = ServiceNowConnector({
        "instance_url": os.environ.get("SERVICENOW_INSTANCE_URL") or os.environ.get("SERVICENOW_URL"),
        "user": os.environ.get("SERVICENOW_USER"),
        "token_env": "SERVICENOW_TOKEN",
    })
    if not conn.configured:
        return {"target": "servicenow", "status": "not_configured"}
    blocked = _egress_ok(conn.instance_url, "servicenow")
    if blocked:
        return {"target": "servicenow", "status": "blocked", "detail": blocked}
    out = conn.create_incident({
        "summary": _safe(f"[ALDECI {verdict['action']}] {finding.get('title')}", 240),
        "description": _safe(
            f"Finding {finding.get('id')} severity={finding.get('severity')} "
            f"cve={finding.get('cve_id')} verdict={verdict['action']} "
            f"source={verdict['verdict_source']}", 2000),
        "urgency": "1" if verdict["action"].startswith("remediate") else "2",
    })
    status = "delivered" if out.status not in ("skipped", "failed") else (
        "not_configured" if out.status == "skipped" else "failed")
    ref = (out.details or {}).get("sys_id") or (out.details or {}).get("number")
    return {"target": "servicenow", "status": status, "ref": ref}


def _deliver_splunk(finding: Dict[str, Any], verdict: Dict[str, Any], org_id: str) -> Dict[str, Any]:
    """Splunk HEC event — best-effort, only when SPLUNK_HEC_URL+TOKEN configured."""
    hec_url = os.environ.get("SPLUNK_HEC_URL")
    hec_token = os.environ.get("SPLUNK_HEC_TOKEN")
    if not hec_url or not hec_token:
        return {"target": "splunk", "status": "not_configured"}
    blocked = _egress_ok(hec_url, "splunk")
    if blocked:
        return {"target": "splunk", "status": "blocked", "detail": blocked}
    import httpx

    event = {
        "event": {
            "source": "aldeci.closed_loop",
            "org_id": org_id,
            "finding_id": finding.get("id"),
            "severity": finding.get("severity"),
            "verdict": verdict["action"],
            "verdict_source": verdict["verdict_source"],
        },
        "sourcetype": "aldeci:decision",
    }
    try:
        resp = httpx.post(hec_url, json=event,
                          headers={"Authorization": f"Splunk {hec_token}"},
                          timeout=10.0, follow_redirects=False)
        resp.raise_for_status()
        return {"target": "splunk", "status": "delivered"}
    except Exception as exc:  # noqa: BLE001
        return {"target": "splunk", "status": "failed", "detail": type(exc).__name__}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


class DecideBody(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=256)
    targets: List[str] = Field(default_factory=lambda: ["jira", "servicenow", "splunk"])


@router.post("/decide")
def decide(body: DecideBody,
           org_id: str = Depends(get_org_id),
           x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> Dict[str, Any]:
    """Render a verdict for an org-owned finding and write it back to the systems of record."""
    # REQ-016-08: org-scoped lookup; cross-org / unknown -> 404 (never act on another org's finding).
    from core.security_findings_engine import SecurityFindingsEngine

    finding = SecurityFindingsEngine().get_finding(body.finding_id, org_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found for this org")

    verdict = _render_verdict(finding, org_id)
    decision = _decision_from_action(verdict["action"])

    # REQ-016-09: dedup key (org_id, finding_id, verdict_hash). Replay returns the receipt.
    verdict_hash = hashlib.sha256(
        f"{org_id}:{body.finding_id}:{verdict['action']}".encode()
    ).hexdigest()[:32]
    con = _conn()
    existing = con.execute(
        "SELECT * FROM closed_loop_deliveries WHERE org_id=? AND finding_id=? AND verdict_hash=?",
        (org_id, body.finding_id, verdict_hash),
    ).fetchone()
    if existing:
        con.close()
        return {
            "decision": existing["decision"],
            "verdict": verdict,
            "receipts": json.loads(existing["receipts"]),
            "evidence_signature": existing["evidence_sig"],
            "evidence_seq": existing["evidence_seq"],
            "deduped": True,
        }

    # Deliver only on block/defer (allow = no ticket noise).
    receipts: List[Dict[str, Any]] = []
    if decision in ("block", "defer"):
        if "jira" in body.targets:
            receipts.append(_deliver_jira(finding, verdict))
        if "servicenow" in body.targets:
            receipts.append(_deliver_servicenow(finding, verdict))
        if "splunk" in body.targets:
            receipts.append(_deliver_splunk(finding, verdict, org_id))

    # REQ-016-10: signed, tamper-evident decision bundle (subject + class + full I/O + ts).
    principal = "anon"
    if x_api_key:
        principal = "key:" + hashlib.sha256(x_api_key.encode()).hexdigest()[:16]
    classification = (
        finding.get("classification_level")
        or os.environ.get("FIXOPS_DEFAULT_CLASSIFICATION")
        or "UNCLASSIFIED"
    )
    bundle = {
        "kind": "closed_loop_decision",
        "org_id": org_id,
        "principal": principal,
        "classification_level": classification,
        "finding_id": body.finding_id,
        "finding_input": {k: finding.get(k) for k in
                          ("id", "title", "severity", "cve_id", "asset_id", "source")},
        "verdict": verdict,
        "decision": decision,
        "receipts": receipts,
        "timestamp": time.time(),
    }
    evidence_sig = None
    evidence_seq = None
    try:
        from core.crypto import sign_evidence
        from core.evidence_chain import EvidenceChain

        signed = sign_evidence(bundle)
        evidence_sig = (signed.get("signature") or {}).get("value") if isinstance(
            signed.get("signature"), dict) else signed.get("signature")
        entry = EvidenceChain().append("closed_loop_decision", signed, org_id)
        evidence_seq = entry.sequence_number
    except Exception as exc:  # noqa: BLE001 - evidence best-effort, decision still recorded
        _logger.warning("closed-loop: evidence sign/append failed: %s", type(exc).__name__)

    con.execute(
        "INSERT OR IGNORE INTO closed_loop_deliveries "
        "(org_id, finding_id, verdict_hash, decision, receipts, evidence_seq, evidence_sig, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (org_id, body.finding_id, verdict_hash, decision, json.dumps(receipts),
         evidence_seq, str(evidence_sig) if evidence_sig else None, time.time()),
    )
    con.commit()
    con.close()

    return {
        "decision": decision,
        "verdict": verdict,
        "receipts": receipts,
        "evidence_signature": evidence_sig,
        "evidence_seq": evidence_seq,
        "deduped": False,
    }


@router.get("/status")
def status(org_id: str = Depends(get_org_id), limit: int = 50) -> Dict[str, Any]:
    """Recent closed-loop decisions for this org (org-scoped)."""
    limit = max(1, min(int(limit), 500))
    con = _conn()
    rows = con.execute(
        "SELECT finding_id, decision, receipts, evidence_seq, evidence_sig, created_at "
        "FROM closed_loop_deliveries WHERE org_id=? ORDER BY created_at DESC LIMIT ?",
        (org_id, limit),
    ).fetchall()
    con.close()
    return {
        "org_id": org_id,
        "total": len(rows),
        "decisions": [
            {
                "finding_id": r["finding_id"],
                "decision": r["decision"],
                "receipts": json.loads(r["receipts"]),
                "evidence_seq": r["evidence_seq"],
                "evidence_signature": r["evidence_sig"],
                "created_at": r["created_at"],
            }
            for r in rows
        ],
    }
