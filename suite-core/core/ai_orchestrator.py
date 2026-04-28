"""AI Agent Orchestration Layer for ALDECI.

Coordinates multiple LLM agents for security decisions:
- Role-based agent assignment (ANALYST, REVIEWER, REMEDIATOR, etc.)
- Multi-agent consensus with confidence scoring
- Sequential and parallel agent pipeline execution
- SQLite-backed task history and stats

Usage::

    from core.ai_orchestrator import AIOrchestrator, AgentRole

    orch = AIOrchestrator()
    task_id = orch.create_task(AgentRole.ANALYST, "Analyse CVE-2024-1234", {"severity": "high"})
    result = orch.execute_task(task_id)
    consensus = orch.multi_agent_consensus("Is this critical?", [AgentRole.ANALYST, AgentRole.REVIEWER])
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]

_DEFAULT_DB = os.environ.get(
    "FIXOPS_ORCHESTRATOR_DB",
    str(Path(os.environ.get("FIXOPS_DATA_DIR", "data")) / "ai_orchestrator.db"),
)

# ---------------------------------------------------------------------------
# Enums & Pydantic models
# ---------------------------------------------------------------------------


class AgentRole(str, Enum):
    ANALYST = "analyst"
    REVIEWER = "reviewer"
    REMEDIATOR = "remediator"
    INVESTIGATOR = "investigator"
    COMPLIANCE_CHECKER = "compliance_checker"
    THREAT_HUNTER = "threat_hunter"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentTask(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: AgentRole
    prompt: str
    context: Dict[str, Any] = Field(default_factory=dict)
    result: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: Optional[str] = None


class ConsensusResult(BaseModel):
    decision: str
    confidence: float = Field(ge=0.0, le=1.0)
    agents_agreed: List[str]
    agents_disagreed: List[str]
    reasoning: str


# ---------------------------------------------------------------------------
# Built-in prompt templates per role
# ---------------------------------------------------------------------------

ROLE_TEMPLATES: Dict[AgentRole, str] = {
    AgentRole.ANALYST: (
        "You are a senior security analyst. Analyse the following security finding and provide "
        "a structured assessment including severity, impact, likelihood, and recommended priority.\n\n"
        "Context: {context}\n\nFinding: {prompt}\n\nProvide: severity assessment, root cause, "
        "affected assets, and recommended action."
    ),
    AgentRole.REVIEWER: (
        "You are a security review specialist. Review the following security decision or finding "
        "for accuracy, completeness, and potential false positives.\n\n"
        "Context: {context}\n\nItem under review: {prompt}\n\nProvide: review verdict (approve/reject/revise), "
        "confidence score (0-100), and rationale."
    ),
    AgentRole.REMEDIATOR: (
        "You are a remediation engineer. Create a concrete remediation plan for the following "
        "security issue, including step-by-step fix instructions and rollback procedures.\n\n"
        "Context: {context}\n\nIssue: {prompt}\n\nProvide: remediation steps, estimated effort, "
        "rollback plan, and validation criteria."
    ),
    AgentRole.INVESTIGATOR: (
        "You are a threat investigator. Conduct a thorough investigation of the following "
        "security event or anomaly, tracing the attack chain and identifying indicators of compromise.\n\n"
        "Context: {context}\n\nEvent: {prompt}\n\nProvide: attack chain reconstruction, IoCs, "
        "affected scope, and containment recommendations."
    ),
    AgentRole.COMPLIANCE_CHECKER: (
        "You are a compliance specialist. Evaluate the following finding or control against "
        "relevant compliance frameworks (SOC2, ISO27001, NIST CSF, PCI-DSS, HIPAA).\n\n"
        "Context: {context}\n\nItem: {prompt}\n\nProvide: framework mapping, compliance gap analysis, "
        "control recommendations, and audit evidence requirements."
    ),
    AgentRole.THREAT_HUNTER: (
        "You are a proactive threat hunter. Analyse the following data or behaviour patterns "
        "to identify hidden threats, lateral movement, or persistence mechanisms.\n\n"
        "Context: {context}\n\nData: {prompt}\n\nProvide: threat hypotheses, hunting queries, "
        "TTPs (MITRE ATT&CK), and detection recommendations."
    ),
}


# ---------------------------------------------------------------------------
# Mock LLM backend (mock-safe — swappable via FIXOPS_LLM_BACKEND env var)
# ---------------------------------------------------------------------------

def _call_llm(role: AgentRole, rendered_prompt: str) -> str:
    """Call the configured LLM backend. Falls back to mock if no backend set."""
    backend = os.environ.get("FIXOPS_LLM_BACKEND", "mock")

    if backend == "mock":
        return _mock_llm_response(role, rendered_prompt)

    if backend == "openrouter":
        return _openrouter_call(rendered_prompt)

    # Unknown backend — fall back to mock
    logger.warning("Unknown FIXOPS_LLM_BACKEND=%r, using mock", backend)
    return _mock_llm_response(role, rendered_prompt)


def _mock_llm_response(role: AgentRole, prompt: str) -> str:
    """Deterministic mock response for testing and airgapped environments."""
    role_responses = {
        AgentRole.ANALYST: (
            "ANALYSIS COMPLETE. Severity: HIGH. Root cause identified in authentication layer. "
            "Affected assets: web-tier, auth-service. Recommended action: immediate patch deployment."
        ),
        AgentRole.REVIEWER: (
            "REVIEW VERDICT: APPROVE. Confidence: 87/100. Finding is valid and well-documented. "
            "No false positive indicators detected. Proceed with remediation."
        ),
        AgentRole.REMEDIATOR: (
            "REMEDIATION PLAN: 1) Apply vendor patch CVE-2024-XXXX. 2) Rotate affected credentials. "
            "3) Update WAF rules. Estimated effort: 2h. Rollback: revert patch, restore credentials."
        ),
        AgentRole.INVESTIGATOR: (
            "INVESTIGATION: Attack chain reconstructed. Initial access via phishing (T1566). "
            "Lateral movement via Pass-the-Hash (T1550.002). IoCs: 192.168.1.100, malware.exe. "
            "Containment: isolate affected hosts."
        ),
        AgentRole.COMPLIANCE_CHECKER: (
            "COMPLIANCE MAPPING: SOC2 CC6.1 (FAIL), ISO27001 A.9.4.2 (PARTIAL), NIST CSF PR.AC-4 (FAIL). "
            "Gap: MFA not enforced. Evidence required: access logs, policy documentation."
        ),
        AgentRole.THREAT_HUNTER: (
            "THREAT HUNT: Hypothesis — APT lateral movement. TTPs: T1078, T1021.002. "
            "Hunting query: EventID=4624 AND LogonType=3. Detection: enable Sysmon event 3."
        ),
    }
    return role_responses.get(role, f"[Mock response for {role.value}]: Task processed successfully.")


def _openrouter_call(prompt: str) -> str:
    """Call OpenRouter API for real LLM inference."""
    try:
        import httpx  # type: ignore
    except ImportError:
        logger.warning("httpx not available — falling back to mock")
        return "[OpenRouter unavailable — mock response]"

    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    model = os.environ.get("FIXOPS_LLM_MODEL", "qwen/qwen3.6-plus:free")

    if not api_key:
        return "[No OPENROUTER_API_KEY — mock response]"

    try:
        resp = httpx.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 1024},
            timeout=30.0,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as exc:
        logger.error("OpenRouter call failed: %s", exc)
        return f"[LLM error: {exc}]"


# ---------------------------------------------------------------------------
# AIOrchestrator — SQLite-backed
# ---------------------------------------------------------------------------

class AIOrchestrator:
    """Coordinate multiple LLM agents for security decisions.

    All tasks and consensus results are persisted to SQLite so history
    survives process restarts.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB init
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS agent_tasks (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT,
                    role        TEXT NOT NULL,
                    prompt      TEXT NOT NULL,
                    context     TEXT NOT NULL DEFAULT '{}',
                    result      TEXT,
                    status      TEXT NOT NULL DEFAULT 'pending',
                    created_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS consensus_results (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT,
                    prompt              TEXT NOT NULL,
                    decision            TEXT NOT NULL,
                    confidence          REAL NOT NULL,
                    agents_agreed       TEXT NOT NULL DEFAULT '[]',
                    agents_disagreed    TEXT NOT NULL DEFAULT '[]',
                    reasoning           TEXT NOT NULL,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tasks_org_id ON agent_tasks(org_id);
                CREATE INDEX IF NOT EXISTS idx_tasks_status ON agent_tasks(status);
                CREATE INDEX IF NOT EXISTS idx_consensus_org_id ON consensus_results(org_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Task management
    # ------------------------------------------------------------------

    def create_task(
        self,
        role: AgentRole,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
        org_id: Optional[str] = None,
    ) -> str:
        """Create and persist a new agent task. Returns task_id."""
        task = AgentTask(
            role=role,
            prompt=prompt,
            context=context or {},
            org_id=org_id,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO agent_tasks (id, org_id, role, prompt, context, result, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    task.id,
                    task.org_id,
                    task.role.value,
                    task.prompt,
                    json.dumps(task.context),
                    task.result,
                    task.status.value,
                    task.created_at.isoformat(),
                ),
            )
        logger.debug("Created task %s role=%s", task.id, role.value)
        return task.id

    def get_task(self, task_id: str) -> Optional[AgentTask]:
        """Retrieve a task by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM agent_tasks WHERE id = ?", (task_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_task(row)

    def execute_task(self, task_id: str) -> AgentTask:
        """Execute a pending task through the LLM and persist the result."""
        task = self.get_task(task_id)
        if task is None:
            raise ValueError(f"Task {task_id!r} not found")
        if task.status not in (TaskStatus.PENDING, TaskStatus.FAILED):
            return task

        # Mark running
        self._update_task_status(task_id, TaskStatus.RUNNING)

        try:
            template = ROLE_TEMPLATES[task.role]
            rendered = template.format(
                context=json.dumps(task.context, indent=2),
                prompt=task.prompt,
            )
            result = _call_llm(task.role, rendered)
            self._update_task_result(task_id, result, TaskStatus.COMPLETED)
            task.result = result
            task.status = TaskStatus.COMPLETED
        except Exception as exc:
            error_msg = f"Task execution failed: {exc}"
            logger.error("Task %s failed: %s", task_id, exc)
            self._update_task_result(task_id, error_msg, TaskStatus.FAILED)
            task.result = error_msg
            task.status = TaskStatus.FAILED

        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("ai_orchestrator.task_completed", {
                    "task_id": task_id,
                    "role": task.role.value,
                    "status": task.status.value,
                    "org_id": task.org_id,
                })
            except Exception:  # noqa: BLE001
                pass

        return task

    def _update_task_status(self, task_id: str, status: TaskStatus) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE agent_tasks SET status = ? WHERE id = ?",
                (status.value, task_id),
            )

    def _update_task_result(self, task_id: str, result: str, status: TaskStatus) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE agent_tasks SET result = ?, status = ? WHERE id = ?",
                (result, status.value, task_id),
            )

    def _row_to_task(self, row: sqlite3.Row) -> AgentTask:
        return AgentTask(
            id=row["id"],
            org_id=row["org_id"],
            role=AgentRole(row["role"]),
            prompt=row["prompt"],
            context=json.loads(row["context"] or "{}"),
            result=row["result"],
            status=TaskStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    # ------------------------------------------------------------------
    # Multi-agent consensus
    # ------------------------------------------------------------------

    def multi_agent_consensus(
        self,
        prompt: str,
        roles: Optional[List[AgentRole]] = None,
        context: Optional[Dict[str, Any]] = None,
        org_id: Optional[str] = None,
    ) -> ConsensusResult:
        """Get consensus from multiple agent roles on a security decision.

        Each role evaluates the prompt independently. Confidence is derived
        from agreement ratio. Result is persisted to SQLite.
        """
        if roles is None:
            roles = [AgentRole.ANALYST, AgentRole.REVIEWER, AgentRole.INVESTIGATOR]

        ctx = context or {}

        # Execute all roles in parallel
        tasks_created: List[str] = []
        for role in roles:
            tid = self.create_task(role, prompt, ctx, org_id=org_id)
            tasks_created.append(tid)

        responses: Dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=min(len(tasks_created), 6)) as pool:
            future_map = {
                pool.submit(self.execute_task, tid): tid
                for tid in tasks_created
            }
            for future in as_completed(future_map):
                tid = future_map[future]
                try:
                    task = future.result()
                    responses[task.role.value] = task.result or ""
                except Exception as exc:
                    logger.error("Consensus task %s failed: %s", tid, exc)
                    responses[tid] = f"[error: {exc}]"

        # Simple consensus: look for APPROVE/REJECT/HIGH/CRITICAL keywords
        approve_keywords = {"approve", "valid", "confirmed", "high", "critical", "recommend"}
        reject_keywords = {"reject", "false positive", "low", "benign", "no threat"}

        agreed: List[str] = []
        disagreed: List[str] = []
        positive_votes = 0

        for role_name, resp in responses.items():
            resp_lower = resp.lower()
            has_approve = any(kw in resp_lower for kw in approve_keywords)
            has_reject = any(kw in resp_lower for kw in reject_keywords)
            if has_approve and not has_reject:
                agreed.append(role_name)
                positive_votes += 1
            elif has_reject and not has_approve:
                disagreed.append(role_name)
            else:
                # Ambiguous — count as agreed if leans positive
                agreed.append(role_name)
                positive_votes += 1

        total = len(roles)
        confidence = round(positive_votes / total, 2) if total > 0 else 0.0

        if confidence >= 0.6:
            decision = "ACTION_REQUIRED"
        elif confidence >= 0.3:
            decision = "INVESTIGATE_FURTHER"
        else:
            decision = "LOW_PRIORITY"

        reasoning = (
            f"{len(agreed)}/{total} agents recommend action. "
            f"Confidence: {confidence:.0%}. "
            f"Agreed: {', '.join(agreed) or 'none'}. "
            f"Disagreed: {', '.join(disagreed) or 'none'}."
        )

        consensus = ConsensusResult(
            decision=decision,
            confidence=confidence,
            agents_agreed=agreed,
            agents_disagreed=disagreed,
            reasoning=reasoning,
        )

        # Persist
        consensus_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO consensus_results
                   (id, org_id, prompt, decision, confidence, agents_agreed, agents_disagreed, reasoning, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    consensus_id,
                    org_id,
                    prompt,
                    consensus.decision,
                    consensus.confidence,
                    json.dumps(consensus.agents_agreed),
                    json.dumps(consensus.agents_disagreed),
                    consensus.reasoning,
                    now,
                ),
            )

        return consensus

    # ------------------------------------------------------------------
    # Pipeline execution
    # ------------------------------------------------------------------

    def chain_agents(
        self,
        tasks: List[Dict[str, Any]],
        org_id: Optional[str] = None,
    ) -> List[AgentTask]:
        """Execute tasks sequentially. Each task's result is injected into
        the next task's context under the key 'previous_result'."""
        results: List[AgentTask] = []
        previous_result: Optional[str] = None

        for task_def in tasks:
            role = AgentRole(task_def["role"]) if isinstance(task_def["role"], str) else task_def["role"]
            ctx = dict(task_def.get("context", {}))
            if previous_result:
                ctx["previous_result"] = previous_result

            tid = self.create_task(role, task_def["prompt"], ctx, org_id=org_id)
            completed = self.execute_task(tid)
            results.append(completed)
            previous_result = completed.result

        return results

    def parallel_agents(
        self,
        tasks: List[Dict[str, Any]],
        org_id: Optional[str] = None,
    ) -> List[AgentTask]:
        """Execute tasks in parallel. All tasks run concurrently."""
        task_ids: List[str] = []
        for task_def in tasks:
            role = AgentRole(task_def["role"]) if isinstance(task_def["role"], str) else task_def["role"]
            ctx = task_def.get("context", {})
            tid = self.create_task(role, task_def["prompt"], ctx, org_id=org_id)
            task_ids.append(tid)

        results: List[AgentTask] = [None] * len(task_ids)  # type: ignore[list-item]

        with ThreadPoolExecutor(max_workers=min(len(task_ids), 6)) as pool:
            future_map = {
                pool.submit(self.execute_task, tid): idx
                for idx, tid in enumerate(task_ids)
            }
            for future in as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as exc:
                    logger.error("Parallel task %s failed: %s", task_ids[idx], exc)

        return [r for r in results if r is not None]

    # ------------------------------------------------------------------
    # History & stats
    # ------------------------------------------------------------------

    def get_task_history(
        self,
        org_id: Optional[str] = None,
        limit: int = 100,
        role: Optional[AgentRole] = None,
        status: Optional[TaskStatus] = None,
    ) -> List[AgentTask]:
        """Return past tasks for an org, optionally filtered."""
        clauses: List[str] = []
        params: List[Any] = []

        if org_id is not None:
            clauses.append("org_id = ?")
            params.append(org_id)
        if role is not None:
            clauses.append("role = ?")
            params.append(role.value)
        if status is not None:
            clauses.append("status = ?")
            params.append(status.value)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM agent_tasks {where} ORDER BY created_at DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()

        return [self._row_to_task(r) for r in rows]

    def get_consensus_stats(
        self,
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return consensus agreement rates and decision distribution."""
        clauses: List[str] = []
        params: List[Any] = []

        if org_id is not None:
            clauses.append("org_id = ?")
            params.append(org_id)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT decision, confidence, agents_agreed, agents_disagreed FROM consensus_results {where}",  # nosec B608
                params,
            ).fetchall()

        if not rows:
            return {
                "total_consensus_runs": 0,
                "avg_confidence": 0.0,
                "decision_distribution": {},
                "avg_agreement_rate": 0.0,
            }

        total = len(rows)
        confidence_sum = 0.0
        agreement_rates: List[float] = []
        decision_counts: Dict[str, int] = {}

        for row in rows:
            confidence_sum += row["confidence"]
            agreed = json.loads(row["agents_agreed"] or "[]")
            disagreed = json.loads(row["agents_disagreed"] or "[]")
            all_agents = len(agreed) + len(disagreed)
            if all_agents > 0:
                agreement_rates.append(len(agreed) / all_agents)
            decision_counts[row["decision"]] = decision_counts.get(row["decision"], 0) + 1

        return {
            "total_consensus_runs": total,
            "avg_confidence": round(confidence_sum / total, 3),
            "decision_distribution": decision_counts,
            "avg_agreement_rate": round(sum(agreement_rates) / len(agreement_rates), 3) if agreement_rates else 0.0,
        }


# ---------------------------------------------------------------------------
# Module-level singleton (lazy init)
# ---------------------------------------------------------------------------

_orchestrator: Optional[AIOrchestrator] = None
_orchestrator_lock = threading.Lock()


def get_orchestrator(db_path: str = _DEFAULT_DB) -> AIOrchestrator:
    """Return (or lazily create) the module-level AIOrchestrator singleton."""
    global _orchestrator
    if _orchestrator is None:
        with _orchestrator_lock:
            if _orchestrator is None:
                _orchestrator = AIOrchestrator(db_path=db_path)
    return _orchestrator


__all__ = [
    "AgentRole",
    "AgentTask",
    "TaskStatus",
    "ConsensusResult",
    "AIOrchestrator",
    "get_orchestrator",
    "ROLE_TEMPLATES",
]
