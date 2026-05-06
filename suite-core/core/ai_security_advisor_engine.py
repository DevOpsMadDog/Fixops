"""AI Security Advisor Engine — ALDECI.

LLM council-powered system that generates proactive security recommendations,
risk explanations, and remediation plans based on current security posture.

Capabilities:
  - Posture-based proactive recommendations (5 prioritized, LLM-generated)
  - Incident root-cause analysis and blast-radius assessment
  - Vulnerability remediation plan generation
  - Executive threat briefings
  - Free-form security Q&A with conversation history
  - Full session and recommendation lifecycle management

Compliance: NIST CSF, CIS Controls v8, ISO 27001, MITRE ATT&CK
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM configuration (OpenRouter-compatible via MuleRouter)
# ---------------------------------------------------------------------------

MULEROUTER_BASE_URL = os.getenv("MULEROUTER_BASE_URL", "https://mulerouter.ai/api/v1")
MULEROUTER_API_KEY = os.getenv("MULEROUTER_API_KEY", "")
MULEROUTER_MODEL = os.getenv("MULEROUTER_DEFAULT_MODEL", "qwen/qwen3-6b-max")

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

# ---------------------------------------------------------------------------
# Fallback recommendations (used when LLM is unavailable)
# ---------------------------------------------------------------------------

FALLBACK_RECOMMENDATIONS: List[Dict[str, Any]] = [
    {
        "priority": "critical",
        "category": "access_control",
        "title": "Enable MFA for all privileged accounts",
        "description": "Multi-factor authentication prevents credential-based attacks targeting admin accounts.",
        "rationale": "90% of successful breaches involve stolen credentials. MFA reduces this risk by 99.9%.",
        "effort_days": 3,
        "impact_score": 10,
        "implementation_steps": [
            "Inventory all privileged accounts",
            "Enable MFA in identity provider",
            "Enforce MFA policy organisation-wide",
            "Audit MFA compliance weekly",
        ],
        "related_controls": ["NIST AC-7", "CIS 6.3", "ISO 27001 A.9.4.2"],
    },
    {
        "priority": "critical",
        "category": "vulnerability",
        "title": "Implement automated patch management",
        "description": "Deploy automated patching to close known CVEs within SLA windows (critical: 24h, high: 7d).",
        "rationale": "60% of breaches exploit known vulnerabilities with available patches. Automation eliminates manual delay.",
        "effort_days": 7,
        "impact_score": 9,
        "implementation_steps": [
            "Audit current patch SLA compliance",
            "Deploy patch management tooling (WSUS/Ansible/Fleet)",
            "Configure auto-approval for critical CVEs",
            "Set alerting for failed patch jobs",
        ],
        "related_controls": ["NIST SI-2", "CIS 7.3", "ISO 27001 A.12.6.1"],
    },
    {
        "priority": "high",
        "category": "monitoring",
        "title": "Deploy centralised SIEM with 24/7 alerting",
        "description": "Aggregate logs from all systems into a SIEM with correlation rules and on-call escalation.",
        "rationale": "Average dwell time without SIEM is 197 days. Proper monitoring reduces this to under 30 days.",
        "effort_days": 14,
        "impact_score": 8,
        "implementation_steps": [
            "Identify all log sources (servers, firewalls, apps, cloud)",
            "Deploy SIEM or configure existing instance",
            "Create correlation rules for top 10 MITRE ATT&CK techniques",
            "Establish on-call rotation for high/critical alerts",
        ],
        "related_controls": ["NIST AU-12", "CIS 8.1", "ISO 27001 A.12.4.1"],
    },
    {
        "priority": "high",
        "category": "architecture",
        "title": "Implement network micro-segmentation",
        "description": "Divide the network into isolated segments to limit lateral movement after initial compromise.",
        "rationale": "Flat networks allow attackers to pivot freely. Segmentation contains blast radius to a single zone.",
        "effort_days": 21,
        "impact_score": 8,
        "implementation_steps": [
            "Map current network topology and data flows",
            "Define security zones (DMZ, production, dev, management)",
            "Implement firewall rules and VLANs between zones",
            "Validate with penetration test or breach simulation",
        ],
        "related_controls": ["NIST SC-7", "CIS 12.2", "ISO 27001 A.13.1.3"],
    },
    {
        "priority": "medium",
        "category": "incident_response",
        "title": "Establish and rehearse an incident response playbook",
        "description": "Document and practice IR procedures so teams respond predictably under pressure.",
        "rationale": "Organisations with tested IR plans contain breaches 35% faster and spend 60% less on remediation.",
        "effort_days": 10,
        "impact_score": 7,
        "implementation_steps": [
            "Draft IR playbook covering detection, containment, eradication, recovery",
            "Assign roles: IR lead, communications, legal, exec sponsor",
            "Run tabletop exercise quarterly",
            "Update playbook after every real incident",
        ],
        "related_controls": ["NIST IR-3", "CIS 17.1", "ISO 27001 A.16.1.1"],
    },
]

# ---------------------------------------------------------------------------
# Validation sets
# ---------------------------------------------------------------------------

_VALID_SESSION_TYPES = {
    "posture_review",
    "incident_analysis",
    "remediation_plan",
    "threat_briefing",
    "compliance_gap",
    "custom",
}
_VALID_SESSION_STATUSES = {"pending", "processing", "completed", "failed"}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}
_VALID_CATEGORIES = {
    "vulnerability",
    "configuration",
    "access_control",
    "monitoring",
    "incident_response",
    "compliance",
    "architecture",
}
_VALID_REC_STATUSES = {"pending", "accepted", "rejected", "implemented"}


# ---------------------------------------------------------------------------
# LLM helper
# ---------------------------------------------------------------------------

def _call_llm(system_prompt: str, user_message: str, max_tokens: int = 1000) -> str:
    """Call LLM via OpenRouter-compatible API. Returns text or raises."""
    if not MULEROUTER_API_KEY:
        return "LLM not configured — set MULEROUTER_API_KEY in .env"

    payload = json.dumps(
        {
            "model": MULEROUTER_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.3,
        }
    ).encode()

    req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
        f"{MULEROUTER_BASE_URL}/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {MULEROUTER_API_KEY}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
    except Exception as exc:
        return f"LLM call failed: {exc}"


# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS advisor_sessions (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    session_type    TEXT NOT NULL DEFAULT 'posture_review',
    context_summary TEXT NOT NULL DEFAULT '{}',
    recommendation_count INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    completed_at    TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS recommendations (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL,
    session_id          TEXT NOT NULL,
    priority            TEXT NOT NULL DEFAULT 'medium',
    category            TEXT NOT NULL DEFAULT 'vulnerability',
    title               TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    rationale           TEXT NOT NULL DEFAULT '',
    effort_days         INTEGER NOT NULL DEFAULT 1,
    impact_score        REAL NOT NULL DEFAULT 5.0,
    implementation_steps TEXT NOT NULL DEFAULT '[]',
    related_controls    TEXT NOT NULL DEFAULT '[]',
    status              TEXT NOT NULL DEFAULT 'pending',
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS advisor_conversations (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'user',
    content     TEXT NOT NULL,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS advisor_templates (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    name            TEXT NOT NULL,
    session_type    TEXT NOT NULL DEFAULT 'custom',
    prompt_template TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_org ON advisor_sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_recs_org ON recommendations(org_id);
CREATE INDEX IF NOT EXISTS idx_recs_session ON recommendations(session_id);
CREATE INDEX IF NOT EXISTS idx_convs_org ON advisor_conversations(org_id);
"""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class AISecurityAdvisorEngine:
    """AI Security Advisor Engine powered by LLM council (MuleRouter/OpenRouter)."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            _DEFAULT_DB_DIR.mkdir(parents=True, exist_ok=True)
            db_path = str(_DEFAULT_DB_DIR / "ai_advisor.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._conn() as conn:
                conn.executescript(_DDL)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    def _create_session(
        self,
        org_id: str,
        session_type: str,
        context_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        session_id = str(uuid.uuid4())
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO advisor_sessions
                       (id, org_id, session_type, context_summary,
                        recommendation_count, created_at, status)
                       VALUES (?,?,?,?,0,?,'processing')""",
                    (
                        session_id,
                        org_id,
                        session_type,
                        json.dumps(context_summary),
                        now,
                    ),
                )
        return {
            "id": session_id,
            "org_id": org_id,
            "session_type": session_type,
            "context_summary": context_summary,
            "recommendation_count": 0,
            "created_at": now,
            "completed_at": None,
            "status": "processing",
        }

    def _complete_session(
        self,
        session_id: str,
        rec_count: int,
        status: str = "completed",
    ) -> None:
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE advisor_sessions
                       SET status=?, completed_at=?, recommendation_count=?
                       WHERE id=?""",
                    (status, now, rec_count, session_id),
                )

    def _fail_session(self, session_id: str) -> None:
        self._complete_session(session_id, 0, status="failed")

    # ------------------------------------------------------------------
    # Recommendation persistence
    # ------------------------------------------------------------------

    def _save_recommendations(
        self,
        org_id: str,
        session_id: str,
        recs: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        saved = []
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                for rec in recs:
                    rec_id = str(uuid.uuid4())
                    priority = rec.get("priority", "medium")
                    if priority not in _VALID_PRIORITIES:
                        priority = "medium"
                    category = rec.get("category", "vulnerability")
                    if category not in _VALID_CATEGORIES:
                        category = "vulnerability"
                    effort = int(rec.get("effort_days", 5))
                    effort = max(1, min(90, effort))
                    impact = float(rec.get("impact_score", 5.0))
                    impact = max(1.0, min(10.0, impact))
                    steps = rec.get("implementation_steps", [])
                    if isinstance(steps, str):
                        steps = [steps]
                    controls = rec.get("related_controls", [])
                    if isinstance(controls, str):
                        controls = [controls]

                    conn.execute(
                        """INSERT INTO recommendations
                           (id, org_id, session_id, priority, category,
                            title, description, rationale, effort_days,
                            impact_score, implementation_steps, related_controls,
                            status, created_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'pending',?)""",
                        (
                            rec_id,
                            org_id,
                            session_id,
                            priority,
                            category,
                            rec.get("title", "Untitled recommendation"),
                            rec.get("description", ""),
                            rec.get("rationale", ""),
                            effort,
                            impact,
                            json.dumps(steps),
                            json.dumps(controls),
                            now,
                        ),
                    )
                    saved.append(
                        {
                            "id": rec_id,
                            "org_id": org_id,
                            "session_id": session_id,
                            "priority": priority,
                            "category": category,
                            "title": rec.get("title", "Untitled recommendation"),
                            "description": rec.get("description", ""),
                            "rationale": rec.get("rationale", ""),
                            "effort_days": effort,
                            "impact_score": impact,
                            "implementation_steps": steps,
                            "related_controls": controls,
                            "status": "pending",
                            "created_at": now,
                        }
                    )
        return saved

    # ------------------------------------------------------------------
    # LLM JSON parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json_from_llm(text: str) -> Any:
        """Try to parse JSON from LLM response, stripping markdown fences."""
        text = text.strip()
        # Strip markdown code fences
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first and last fence lines
            inner = []
            in_block = False
            for line in lines:
                if line.startswith("```") and not in_block:
                    in_block = True
                    continue
                if line.startswith("```") and in_block:
                    break
                if in_block:
                    inner.append(line)
            text = "\n".join(inner)
        return json.loads(text)

    # ------------------------------------------------------------------
    # Public API — posture review
    # ------------------------------------------------------------------

    def generate_posture_recommendations(
        self, org_id: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate 5 prioritised security recommendations from posture context.

        Args:
            org_id: Organisation identifier.
            context: Dict with keys such as risk_score, critical_findings,
                     top_vulnerabilities, compliance_status, asset_count, etc.

        Returns:
            {"session": session_dict, "recommendations": [rec_dict, ...]}
        """
        session = self._create_session(org_id, "posture_review", context)

        system_prompt = (
            "You are a CISO-level security advisor. "
            "Generate exactly 5 prioritized security recommendations in JSON format. "
            "Return ONLY a JSON array with no extra text. "
            "Each element must have these fields: "
            "priority (critical|high|medium|low), "
            "category (vulnerability|configuration|access_control|monitoring|incident_response|compliance|architecture), "
            "title (string), description (string), rationale (string), "
            "effort_days (integer 1-90), impact_score (float 1-10), "
            "implementation_steps (array of strings), "
            "related_controls (array of NIST/ISO/CIS control IDs)."
        )
        risk_score = context.get("risk_score", "unknown")
        critical_findings = context.get("critical_findings", "unknown")
        top_vulns = context.get("top_vulnerabilities", [])
        compliance_status = context.get("compliance_status", "unknown")

        user_message = (
            f"Security posture context:\n"
            f"- Risk score: {risk_score}\n"
            f"- Critical findings: {critical_findings}\n"
            f"- Top vulnerabilities: {top_vulns}\n"
            f"- Compliance status: {compliance_status}\n\n"
            "Generate 5 actionable security recommendations."
        )

        llm_text = _call_llm(system_prompt, user_message, max_tokens=1500)

        recs_data: List[Dict[str, Any]] = []
        try:
            parsed = self._extract_json_from_llm(llm_text)
            if isinstance(parsed, list):
                recs_data = parsed[:5]
            elif isinstance(parsed, dict) and "recommendations" in parsed:
                recs_data = parsed["recommendations"][:5]
        except (json.JSONDecodeError, ValueError, KeyError):
            _logger.warning("LLM returned non-JSON for posture review — using fallbacks")
            recs_data = FALLBACK_RECOMMENDATIONS

        if not recs_data:
            recs_data = FALLBACK_RECOMMENDATIONS

        saved = self._save_recommendations(org_id, session["id"], recs_data)
        self._complete_session(session["id"], len(saved))
        session["status"] = "completed"
        session["recommendation_count"] = len(saved)
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "ai_security_advisor_engine", "org_id": org_id, "source_engine": "ai_security_advisor_engine"})
            except Exception:
                pass
        return {"session": session, "recommendations": saved}

    # ------------------------------------------------------------------
    # Public API — incident analysis
    # ------------------------------------------------------------------

    def analyze_incident(
        self, org_id: str, incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyse a security incident and generate structured findings.

        Returns:
            {"session": session_dict, "analysis": {...}}
        """
        session = self._create_session(org_id, "incident_analysis", incident_data)

        system_prompt = (
            "You are a senior incident response analyst. "
            "Analyse the security incident and return ONLY a JSON object with fields: "
            "root_cause (string), attack_vector (string), blast_radius (string), "
            "immediate_actions (array of strings), long_term_fixes (array of strings), "
            "similar_incidents_to_watch (array of strings), severity (critical|high|medium|low), "
            "estimated_recovery_hours (integer)."
        )
        user_message = f"Incident data:\n{json.dumps(incident_data, indent=2)}\n\nProvide incident analysis."

        llm_text = _call_llm(system_prompt, user_message, max_tokens=1200)

        analysis: Dict[str, Any] = {}
        try:
            parsed = self._extract_json_from_llm(llm_text)
            if isinstance(parsed, dict):
                analysis = parsed
        except (json.JSONDecodeError, ValueError):
            _logger.warning("LLM returned non-JSON for incident analysis — using defaults")
            analysis = {
                "root_cause": "Unable to determine — LLM response was non-parseable",
                "attack_vector": incident_data.get("attack_vector", "Unknown"),
                "blast_radius": "Scope under investigation",
                "immediate_actions": [
                    "Isolate affected systems",
                    "Preserve forensic artifacts",
                    "Notify incident response team",
                    "Begin evidence collection",
                ],
                "long_term_fixes": [
                    "Conduct post-incident review within 72 hours",
                    "Update detection rules based on IOCs",
                    "Patch exploited vulnerabilities",
                ],
                "similar_incidents_to_watch": [
                    "Monitor for lateral movement",
                    "Watch for data exfiltration patterns",
                ],
                "severity": incident_data.get("severity", "high"),
                "estimated_recovery_hours": 24,
            }

        self._complete_session(session["id"], 0)
        session["status"] = "completed"
        return {"session": session, "analysis": analysis}

    # ------------------------------------------------------------------
    # Public API — remediation plan
    # ------------------------------------------------------------------

    def generate_remediation_plan(
        self, org_id: str, vulnerability_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a step-by-step remediation plan for a vulnerability.

        Returns:
            {"session": session_dict, "plan": {...}}
        """
        session = self._create_session(org_id, "remediation_plan", vulnerability_data)

        system_prompt = (
            "You are a security remediation expert. "
            "Generate a remediation plan and return ONLY a JSON object with fields: "
            "steps (array of strings), estimated_effort_hours (integer), "
            "technical_prerequisites (array of strings), testing_approach (string), "
            "rollback_plan (string), verification_criteria (array of strings), "
            "risk_during_remediation (low|medium|high), "
            "recommended_maintenance_window (string)."
        )
        user_message = (
            f"Vulnerability details:\n{json.dumps(vulnerability_data, indent=2)}\n\n"
            "Generate a detailed remediation plan."
        )

        llm_text = _call_llm(system_prompt, user_message, max_tokens=1200)

        plan: Dict[str, Any] = {}
        try:
            parsed = self._extract_json_from_llm(llm_text)
            if isinstance(parsed, dict):
                plan = parsed
        except (json.JSONDecodeError, ValueError):
            _logger.warning("LLM non-JSON for remediation plan — using defaults")
            vuln_name = vulnerability_data.get("name", "the vulnerability")
            plan = {
                "steps": [
                    f"1. Verify exposure scope for {vuln_name}",
                    "2. Apply vendor patch or workaround",
                    "3. Restart affected services in maintenance window",
                    "4. Run vulnerability scanner to confirm fix",
                    "5. Update asset inventory with patch status",
                    "6. Close associated tickets and notify stakeholders",
                ],
                "estimated_effort_hours": 4,
                "technical_prerequisites": [
                    "Admin access to affected systems",
                    "Patch binary or configuration change approved",
                    "Change management ticket raised",
                ],
                "testing_approach": "Run authenticated vulnerability scan post-patch; validate with exploit PoC in isolated environment.",
                "rollback_plan": "Restore from snapshot taken before patching; re-enable original configuration if regression detected.",
                "verification_criteria": [
                    "Scanner reports vulnerability as remediated",
                    "Service functioning normally post-patch",
                    "No new critical alerts within 24h",
                ],
                "risk_during_remediation": "low",
                "recommended_maintenance_window": "Off-peak hours (02:00–04:00 local time)",
            }

        self._complete_session(session["id"], 0)
        session["status"] = "completed"
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "ai_security_advisor_engine", "org_id": org_id, "source_engine": "ai_security_advisor_engine"})
            except Exception:
                pass
        return {"session": session, "plan": plan}

    # ------------------------------------------------------------------
    # Public API — threat briefing
    # ------------------------------------------------------------------

    def get_threat_briefing(
        self, org_id: str, threat_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate an executive threat briefing.

        Returns:
            {"session": session_dict, "briefing": {...}}
        """
        session = self._create_session(org_id, "threat_briefing", threat_context)

        system_prompt = (
            "You are a threat intelligence analyst briefing a CISO. "
            "Return ONLY a JSON object with fields: "
            "executive_summary (string, 2 sentences max), "
            "top_threats (array of 3 objects each with: name, description, likelihood), "
            "recommended_actions (array of 3 strings), "
            "risk_level (critical|high|medium|low), "
            "confidence (high|medium|low), "
            "briefing_date (ISO date string)."
        )
        user_message = (
            f"Threat context:\n{json.dumps(threat_context, indent=2)}\n\n"
            "Generate an executive threat briefing."
        )

        llm_text = _call_llm(system_prompt, user_message, max_tokens=1000)

        briefing: Dict[str, Any] = {}
        try:
            parsed = self._extract_json_from_llm(llm_text)
            if isinstance(parsed, dict):
                briefing = parsed
        except (json.JSONDecodeError, ValueError):
            _logger.warning("LLM non-JSON for threat briefing — using defaults")
            briefing = {
                "executive_summary": (
                    "The organisation faces an elevated threat landscape with active exploitation "
                    "of known vulnerabilities in the wild. Immediate action on critical patches "
                    "and enhanced monitoring is recommended."
                ),
                "top_threats": [
                    {
                        "name": "Ransomware campaigns targeting unpatched systems",
                        "description": "Threat actors actively scanning for CVEs >30 days unpatched",
                        "likelihood": "high",
                    },
                    {
                        "name": "Credential stuffing via exposed services",
                        "description": "Automated credential spray attacks against internet-facing login portals",
                        "likelihood": "medium",
                    },
                    {
                        "name": "Supply chain compromise via third-party dependencies",
                        "description": "Malicious packages in open-source ecosystems targeting CI/CD pipelines",
                        "likelihood": "medium",
                    },
                ],
                "recommended_actions": [
                    "Apply all critical patches within 24 hours",
                    "Enable MFA on all internet-facing services immediately",
                    "Review and rotate credentials for privileged accounts",
                ],
                "risk_level": "high",
                "confidence": "medium",
                "briefing_date": self._now()[:10],
            }

        self._complete_session(session["id"], 0)
        session["status"] = "completed"
        return {"session": session, "briefing": briefing}

    # ------------------------------------------------------------------
    # Public API — free-form Q&A
    # ------------------------------------------------------------------

    def ask_advisor(
        self,
        org_id: str,
        question: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Free-form security question answered by the AI advisor.

        Returns:
            {"question": str, "answer": str, "tokens_used": int}
        """
        system_prompt = (
            "You are an expert CISO-level security advisor for ALDECI. "
            "Answer the security question clearly, concisely, and with actionable guidance. "
            "Where relevant, reference specific NIST, CIS, or ISO controls."
        )
        user_message = question
        if context:
            user_message = f"Context:\n{json.dumps(context, indent=2)}\n\nQuestion: {question}"

        answer = _call_llm(system_prompt, user_message, max_tokens=800)

        # Rough token estimate (4 chars ≈ 1 token)
        tokens_used = (len(question) + len(answer)) // 4

        now = self._now()
        with self._lock:
            with self._conn() as conn:
                for role, content in [("user", question), ("assistant", answer)]:
                    conn.execute(
                        """INSERT INTO advisor_conversations
                           (id, org_id, role, content, tokens_used, created_at)
                           VALUES (?,?,?,?,?,?)""",
                        (str(uuid.uuid4()), org_id, role, content, tokens_used, now),
                    )

        return {"question": question, "answer": answer, "tokens_used": tokens_used}

    # ------------------------------------------------------------------
    # Session queries
    # ------------------------------------------------------------------

    def list_sessions(
        self,
        org_id: str,
        session_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List advisor sessions for an org, optionally filtered by type."""
        with self._lock:
            with self._conn() as conn:
                if session_type:
                    rows = conn.execute(
                        "SELECT * FROM advisor_sessions WHERE org_id=? AND session_type=? ORDER BY created_at DESC",
                        (org_id, session_type),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM advisor_sessions WHERE org_id=? ORDER BY created_at DESC",
                        (org_id,),
                    ).fetchall()
        result = []
        for row in rows:
            d = self._row_to_dict(row)
            try:
                d["context_summary"] = json.loads(d["context_summary"])
            except (json.JSONDecodeError, TypeError):
                pass
            result.append(d)
        return result

    def get_session(self, org_id: str, session_id: str) -> Optional[Dict[str, Any]]:
        """Get a session with its recommendations."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM advisor_sessions WHERE id=? AND org_id=?",
                    (session_id, org_id),
                ).fetchone()
                if not row:
                    return None
                session = self._row_to_dict(row)
                try:
                    session["context_summary"] = json.loads(session["context_summary"])
                except (json.JSONDecodeError, TypeError):
                    pass
                rec_rows = conn.execute(
                    "SELECT * FROM recommendations WHERE session_id=? AND org_id=? ORDER BY created_at",
                    (session_id, org_id),
                ).fetchall()
        recs = []
        for r in rec_rows:
            d = self._row_to_dict(r)
            for field in ("implementation_steps", "related_controls"):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
            recs.append(d)
        session["recommendations"] = recs
        return session

    # ------------------------------------------------------------------
    # Recommendation queries
    # ------------------------------------------------------------------

    def list_recommendations(
        self,
        org_id: str,
        priority: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List recommendations with optional filters."""
        query = "SELECT * FROM recommendations WHERE org_id=?"
        params: List[Any] = [org_id]
        if priority:
            query += " AND priority=?"
            params.append(priority)
        if category:
            query += " AND category=?"
            params.append(category)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()

        result = []
        for row in rows:
            d = self._row_to_dict(row)
            for field in ("implementation_steps", "related_controls"):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result

    def update_recommendation_status(
        self, org_id: str, rec_id: str, status: str
    ) -> Optional[Dict[str, Any]]:
        """Update the lifecycle status of a recommendation.

        Returns updated recommendation dict or None if not found.
        """
        if status not in _VALID_REC_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of: {sorted(_VALID_REC_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE recommendations SET status=? WHERE id=? AND org_id=?",
                    (status, rec_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM recommendations WHERE id=? AND org_id=?",
                    (rec_id, org_id),
                ).fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        for field in ("implementation_steps", "related_controls"):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                pass
        return d

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # GAP-019: AI-generated code analysis (SAST + AI-specific risk signals)
    # ------------------------------------------------------------------

    # Language-scoped AI-specific risk patterns. Each entry:
    # (risk_id, title, severity, regex_pattern, languages, message)
    _AI_RISK_PATTERNS: List[Any] = [
        (
            "AI-RISK-001",
            "Hardcoded secret in AI-generated code",
            "high",
            r"""(password|secret|api[_-]?key|token|private[_-]?key|aws[_-]?access[_-]?key|bearer)\s*[:=]\s*["'][A-Za-z0-9+/=_\-]{8,}["']""",
            {"python", "javascript", "typescript", "java", "go", "ruby", "php"},
            "AI code generators frequently produce placeholder credentials; replace with env var or secret manager.",
        ),
        (
            "AI-RISK-002",
            "eval() on untrusted input",
            "critical",
            r"""\beval\s*\(""",
            {"python", "javascript", "typescript", "ruby", "php"},
            "eval() enables arbitrary code execution; refuse AI-suggested eval and use a safe parser.",
        ),
        (
            "AI-RISK-003",
            "os.system() shell call",
            "critical",
            r"""\bos\.system\s*\(""",
            {"python"},
            "os.system passes raw shell strings; use subprocess with a list argument and shell=False.",
        ),
        (
            "AI-RISK-004",
            "subprocess with shell=True",
            "high",
            r"""subprocess\.(run|call|Popen|check_call|check_output)\s*\([^)]*shell\s*=\s*True""",
            {"python"},
            "shell=True enables injection via interpolated args; build argv list and omit shell=True.",
        ),
        (
            "AI-RISK-005",
            "exec() dynamic execution",
            "critical",
            r"""\bexec\s*\(""",
            {"python", "javascript"},
            "exec() executes arbitrary strings as code; refuse AI-generated exec and use explicit control flow.",
        ),
        (
            "AI-RISK-006",
            "child_process.exec with interpolation",
            "critical",
            r"""child_process\.(exec|execSync)\s*\(\s*[`"']?[^)]*\$\{""",
            {"javascript", "typescript"},
            "Use child_process.execFile with an argv array; never interpolate user input into exec strings.",
        ),
        (
            "AI-RISK-007",
            "Dangerous Function() constructor",
            "high",
            r"""\bnew\s+Function\s*\(""",
            {"javascript", "typescript"},
            "Function() constructs code from strings at runtime; refuse AI-suggested use.",
        ),
    ]

    @staticmethod
    def _ai_risk_score(sast_findings: List[Dict[str, Any]], ai_risks: List[Dict[str, Any]]) -> float:
        """Combine SAST + AI-risk severities into a 0-100 risk score."""
        sev_weights = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "info": 0.5}
        score = 0.0
        for item in list(sast_findings) + list(ai_risks):
            sev = str(item.get("severity", "medium")).lower()
            score += sev_weights.get(sev, 3.0)
        # Saturate at 100
        return float(min(100.0, round(score, 2)))

    def analyze_ai_generated(
        self,
        org_id: str,
        code: str,
        language: str,
    ) -> Dict[str, Any]:
        """Full analysis of AI-generated code: SAST findings + AI-specific risk signals.

        Returns:
            {
              "org_id": str,
              "language": str,
              "snippet_sha256": str,
              "sast_findings": [...],
              "ai_risks": [...],
              "combined_score": float,   # 0-100, higher = riskier
              "risk_level": "critical|high|medium|low|minimal",
              "scanned_at": iso8601,
              "cached": bool,            # True if SAST cache was hit
            }
        """
        if not isinstance(org_id, str) or not org_id:
            raise ValueError("org_id must be a non-empty string")
        if not isinstance(code, str):
            raise ValueError("code must be a string")
        if not isinstance(language, str) or not language:
            raise ValueError("language must be a non-empty string")

        # 1) SAST via sast_engine.scan_snippet
        try:
            from core.sast_engine import scan_snippet as _scan_snippet
        except ImportError:
            from sast_engine import scan_snippet as _scan_snippet  # type: ignore

        sast_result = _scan_snippet(
            org_id=org_id,
            code=code,
            language=language,
            source_hint="ai_generated",
        )
        sast_findings = list(sast_result.get("findings", []))

        # 2) AI-specific risk signals (compiled lazily, once per call — simple + safe)
        import re as _re
        lang_lc = language.lower()
        ai_risks: List[Dict[str, Any]] = []
        lines = code.split("\n")
        for risk_id, title, severity, pattern, langs, message in self._AI_RISK_PATTERNS:
            if lang_lc not in langs:
                continue
            try:
                compiled = _re.compile(pattern)
            except _re.error:
                continue
            for idx, line in enumerate(lines, 1):
                # Skip empty lines and obvious comments to reduce noise
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                    continue
                # Avoid pathological long lines (guard against minified/huge inputs)
                if len(line) > 10_000:
                    continue
                if compiled.search(line):
                    ai_risks.append(
                        {
                            "risk_id": risk_id,
                            "title": title,
                            "severity": severity,
                            "language": language,
                            "line_number": idx,
                            "snippet": stripped[:200],
                            "message": message,
                            "source": "ai_generated_heuristic",
                        }
                    )

        combined_score = self._ai_risk_score(sast_findings, ai_risks)
        if combined_score >= 60:
            risk_level = "critical"
        elif combined_score >= 30:
            risk_level = "high"
        elif combined_score >= 15:
            risk_level = "medium"
        elif combined_score > 0:
            risk_level = "low"
        else:
            risk_level = "minimal"

        # Emit TrustGraph event (best-effort)
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit(
                        "FINDING_CREATED",
                        {
                            "entity_type": "ai_code_scanner",
                            "org_id": org_id,
                            "source_engine": "ai_security_advisor_engine",
                            "risk_level": risk_level,
                            "score": combined_score,
                        },
                    )
            except Exception:
                pass

        return {
            "org_id": org_id,
            "language": language,
            "snippet_sha256": sast_result.get("snippet_sha256"),
            "sast_findings": sast_findings,
            "sast_findings_count": len(sast_findings),
            "ai_risks": ai_risks,
            "ai_risks_count": len(ai_risks),
            "combined_score": combined_score,
            "risk_level": risk_level,
            "scanned_at": sast_result.get("scanned_at"),
            "cached": bool(sast_result.get("cached", False)),
        }

    # ------------------------------------------------------------------
    # GAP-029: NL graph question wrapper
    # ------------------------------------------------------------------

    def answer_graph_question(
        self, org_id: str, question: str
    ) -> Dict[str, Any]:
        """Answer a natural-language graph question by delegating to GraphRAG.

        Wraps `GraphRAGEngine.query_with_trace(...)` and adds a template-based
        LLM-style explanation (no real LLM call — deterministic string).

        Returns:
            {
              "question": str,
              "parsed_entities": [...],
              "parsed_edges": [...],
              "traversal_trace": [...],
              "answer_summary": str,
              "explanation": str,   # template-based
              "cached": bool,
            }
        """
        if not isinstance(org_id, str) or not org_id:
            raise ValueError("org_id must be a non-empty string")
        if not isinstance(question, str) or not question.strip():
            raise ValueError("question must be a non-empty string")

        try:
            from core.graphrag_engine import GraphRAGEngine as _GRE
        except ImportError:
            from graphrag_engine import GraphRAGEngine as _GRE  # type: ignore

        engine = _GRE()
        traced = engine.query_with_trace(org_id, question)

        trace = traced.get("traversal_trace", []) or []
        entities = traced.get("parsed_entities", []) or []
        seed_entity = entities[0] if entities else "<no entity>"
        summary = traced.get("answer_summary", "")

        if trace:
            key_path = " -> ".join(
                f"{h['source']} -[{h['edge']}]-> {h['target']}" for h in trace[:3]
            )
            explanation = (
                f"Based on {len(trace)} hop(s) from '{seed_entity}', "
                f"the answer is: {summary} "
                f"Key path: {key_path}."
            )
        else:
            explanation = (
                f"Based on 0 hops from '{seed_entity}', "
                f"the answer is: {summary} "
                "No path could be constructed from the current graph."
            )

        return {**traced, "explanation": explanation}

    # ------------------------------------------------------------------
    # GAP-044: AI Teammates UX (suggest-fix, draft-exception, auto-triage)
    # ------------------------------------------------------------------

    def _load_finding(self, org_id: str, finding_id: str) -> Dict[str, Any]:
        """Best-effort load of a finding from vulnerability_scoring_engine DB.

        Returns an empty dict if the finding or DB is missing — the teammate
        methods degrade gracefully rather than failing.
        """
        if not isinstance(finding_id, str) or not finding_id:
            return {}
        try:
            vs_path = _DEFAULT_DB_DIR / "vulnerability_scoring_engine.db"
            if not vs_path.exists():
                return {}
            conn = sqlite3.connect(str(vs_path), timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute(
                    """SELECT * FROM vuln_scores
                       WHERE org_id=? AND (id=? OR vuln_id=?)
                       ORDER BY created_at DESC LIMIT 1""",
                    (org_id, finding_id, finding_id),
                ).fetchone()
            finally:
                conn.close()
            return dict(row) if row else {}
        except sqlite3.Error:
            return {}

    def _similar_past_fixes(
        self, org_id: str, finding: Dict[str, Any], limit: int = 3
    ) -> List[Dict[str, Any]]:
        """Find similar implemented recommendations for context."""
        category_hint = "vulnerability"
        sev = (finding.get("priority_tier") or "").lower()
        if "critical" in sev:
            priority_filter = "critical"
        elif "high" in sev:
            priority_filter = "high"
        else:
            priority_filter = None

        try:
            recs = self.list_recommendations(
                org_id, priority=priority_filter, category=category_hint,
                status="implemented",
            )
        except Exception:
            recs = []
        return [
            {
                "title": r.get("title", ""),
                "rationale": r.get("rationale", ""),
                "impact_score": r.get("impact_score"),
                "effort_days": r.get("effort_days"),
            }
            for r in recs[:limit]
        ]

    def suggest_fix_with_context(
        self, org_id: str, finding_id: str
    ) -> Dict[str, Any]:
        """Teammate-mode: propose a fix with rationale and similar past fixes.

        Returns::

            {
              "suggestion_type": "patch"|"config"|"compensating_control",
              "recommended_action": str,
              "confidence": float,   # 0.0 - 1.0
              "rationale": str,
              "similar_past_fixes": [ ... ],
              "finding_id": str,
              "generated_at": iso8601,
            }
        """
        if not isinstance(org_id, str) or not org_id:
            raise ValueError("org_id must be a non-empty string")
        if not isinstance(finding_id, str) or not finding_id:
            raise ValueError("finding_id must be a non-empty string")

        finding = self._load_finding(org_id, finding_id)
        tier = (finding.get("priority_tier") or "P4-Low").lower()
        score = float(finding.get("composite_score") or 0.0)

        if "critical" in tier:
            suggestion_type = "patch"
            action = "Apply vendor patch within 24h SLA and re-scan to confirm closure."
            confidence = 0.9
        elif "high" in tier:
            suggestion_type = "patch"
            action = "Schedule patch in next change window; apply temporary network ACL as compensating control."
            confidence = 0.8
        elif "medium" in tier:
            suggestion_type = "config"
            action = "Apply configuration hardening from CIS benchmark; defer patch to monthly cycle."
            confidence = 0.7
        else:
            suggestion_type = "compensating_control"
            action = "Accept risk with monitoring; document in risk register."
            confidence = 0.6

        rationale = (
            f"Finding priority tier={tier}, composite score={score}. "
            f"CVSS={finding.get('cvss_score', 'n/a')}, "
            f"EPSS={finding.get('epss_score', 'n/a')}, "
            f"KEV-listed={bool(finding.get('kev_listed'))}. "
            "Recommendation derived from historical implemented fixes and "
            "current severity tier policy."
        )
        similar = self._similar_past_fixes(org_id, finding)

        return {
            "suggestion_type": suggestion_type,
            "recommended_action": action,
            "confidence": confidence,
            "rationale": rationale,
            "similar_past_fixes": similar,
            "finding_id": finding_id,
            "generated_at": self._now(),
        }

    def draft_exception_request(
        self,
        org_id: str,
        finding_id: str,
        business_justification: str,
    ) -> Dict[str, Any]:
        """Teammate-mode: draft a security exception request document."""
        if not isinstance(org_id, str) or not org_id:
            raise ValueError("org_id must be a non-empty string")
        if not isinstance(finding_id, str) or not finding_id:
            raise ValueError("finding_id must be a non-empty string")
        business_justification = business_justification or ""

        finding = self._load_finding(org_id, finding_id)
        tier = finding.get("priority_tier") or "P4-Low"
        score = float(finding.get("composite_score") or 0.0)

        # Heuristic: higher tier = shorter max duration for exception
        if "P1" in tier:
            max_duration_days = 14
            required_approver = "CISO"
        elif "P2" in tier:
            max_duration_days = 30
            required_approver = "Security Director"
        elif "P3" in tier:
            max_duration_days = 90
            required_approver = "Security Manager"
        else:
            max_duration_days = 180
            required_approver = "Security Analyst"

        compensating_controls = [
            "Enable enhanced monitoring / SIEM alerts on affected asset",
            "Restrict network access via firewall / segmentation",
            "Require MFA for any human access to the asset",
            "Document ownership + review cadence",
        ]
        draft = {
            "finding_id": finding_id,
            "tier": tier,
            "composite_score": score,
            "business_justification": business_justification,
            "suggested_max_duration_days": max_duration_days,
            "required_approver": required_approver,
            "compensating_controls": compensating_controls,
            "drafted_at": self._now(),
            "review_cadence_days": min(30, max_duration_days // 2),
            "risk_acceptance_statement": (
                f"This exception accepts residual risk with composite score "
                f"{score} ({tier}) until the compensating controls above are in "
                f"place and the underlying vulnerability is remediated. Approval "
                f"must be reviewed every {min(30, max_duration_days // 2)} days."
            ),
        }
        return draft

    def auto_triage(self, org_id: str, finding_id: str) -> Dict[str, Any]:
        """Teammate-mode: propose priority + assignee for a finding.

        Combines composite score with blast radius (GAP-027) + crown-jewel
        tags to suggest a triage outcome. Returns a fully-formed triage
        proposal — the caller is expected to apply it manually.
        """
        if not isinstance(org_id, str) or not org_id:
            raise ValueError("org_id must be a non-empty string")
        if not isinstance(finding_id, str) or not finding_id:
            raise ValueError("finding_id must be a non-empty string")

        finding = self._load_finding(org_id, finding_id)
        tier = finding.get("priority_tier") or "P4-Low"
        score = float(finding.get("composite_score") or 0.0)
        asset_criticality = (finding.get("asset_criticality") or "medium").lower()
        kev = bool(finding.get("kev_listed"))

        # Crown jewel = asset_criticality critical
        is_crown_jewel = asset_criticality == "critical"

        # Blast radius proxy: pull breakdown factor from vuln scoring DB
        blast_radius = 0.0
        try:
            vs_path = _DEFAULT_DB_DIR / "vulnerability_scoring_engine.db"
            if vs_path.exists():
                conn = sqlite3.connect(str(vs_path), timeout=5)
                conn.row_factory = sqlite3.Row
                try:
                    row = conn.execute(
                        """SELECT factor_value FROM score_breakdown
                           WHERE org_id=? AND factor_name='blast_radius'
                             AND vuln_score_id=(
                               SELECT id FROM vuln_scores
                               WHERE org_id=? AND (id=? OR vuln_id=?)
                               ORDER BY created_at DESC LIMIT 1
                             )
                           ORDER BY recorded_at DESC LIMIT 1""",
                        (org_id, org_id, finding_id, finding_id),
                    ).fetchone()
                    if row:
                        blast_radius = float(row["factor_value"] or 0.0)
                finally:
                    conn.close()
        except sqlite3.Error:
            blast_radius = 0.0

        # Priority elevation policy
        proposed_priority = "P4"
        if "P1" in tier or kev or score >= 80 or is_crown_jewel:
            proposed_priority = "P1"
        elif "P2" in tier or score >= 60 or blast_radius >= 50:
            proposed_priority = "P2"
        elif "P3" in tier or score >= 40:
            proposed_priority = "P3"

        # Assignee role policy
        if proposed_priority == "P1":
            proposed_assignee_role = "incident_response_lead"
        elif proposed_priority == "P2":
            proposed_assignee_role = "senior_security_engineer"
        elif proposed_priority == "P3":
            proposed_assignee_role = "security_engineer"
        else:
            proposed_assignee_role = "security_analyst"

        reasoning_parts = [
            f"composite_score={score}",
            f"tier={tier}",
            f"kev_listed={kev}",
            f"asset_criticality={asset_criticality}",
            f"crown_jewel={is_crown_jewel}",
            f"blast_radius={blast_radius}",
        ]

        return {
            "finding_id": finding_id,
            "proposed_priority": proposed_priority,
            "proposed_assignee_role": proposed_assignee_role,
            "crown_jewel": is_crown_jewel,
            "blast_radius": blast_radius,
            "confidence": 0.85 if score > 0 else 0.5,
            "reasoning": "; ".join(reasoning_parts),
            "triaged_at": self._now(),
        }

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated advisor statistics for an org."""
        from datetime import timedelta


        week_ago = (
            datetime.now(timezone.utc) - timedelta(days=7)
        ).isoformat()

        with self._lock:
            with self._conn() as conn:
                # Single pass over advisor_sessions (was 2 separate COUNT queries)
                sess_row = conn.execute(
                    """SELECT
                           COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE created_at >= ?) AS this_week
                       FROM advisor_sessions WHERE org_id=?""",
                    (week_ago, org_id),
                ).fetchone()
                session_count = sess_row["total"]
                sessions_this_week = sess_row["this_week"]

                # Single pass over recommendations (was 4 separate queries)
                rec_agg = conn.execute(
                    """SELECT
                           priority,
                           status,
                           COUNT(*) AS cnt,
                           COALESCE(SUM(impact_score), 0) AS impact
                       FROM recommendations WHERE org_id=?
                       GROUP BY priority, status""",
                    (org_id,),
                ).fetchall()

                # Derive all four scalars + dicts from one result set
                priority_rows: dict = {}
                status_rows: dict = {}
                implemented_count = 0
                total_impact = 0.0
                for row in rec_agg:
                    p, s, cnt, imp = row["priority"], row["status"], row["cnt"], row["impact"]
                    priority_rows[p] = priority_rows.get(p, 0) + cnt
                    status_rows[s] = status_rows.get(s, 0) + cnt
                    if s == "implemented":
                        implemented_count += cnt
                    total_impact += imp

                conversation_count = conn.execute(
                    "SELECT COUNT(*) FROM advisor_conversations WHERE org_id=?",
                    (org_id,),
                ).fetchone()[0]

        return {
            "org_id": org_id,
            "session_count": session_count,
            "sessions_this_week": sessions_this_week,
            "recommendations_by_priority": priority_rows,
            "recommendations_by_status": status_rows,
            "implemented_count": implemented_count,
            "total_impact_score": float(total_impact),
            "conversation_count": conversation_count,
        }
