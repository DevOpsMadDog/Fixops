"""
ALDECI Prometheus Alerts Engine.

In-memory catalog of preset Prometheus alert rules grouped by:
  - security
  - availability
  - performance
  - compliance

Provides a SAFE PromQL-subset interpreter for evaluating alert expressions
against an injected sample_metrics dict (no eval/exec; pure recursive descent).

Singleton:
    get_prometheus_alerts_engine()

Vision Pillars: V3 (Decision Intelligence), V8 (Observability)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rule data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertRule:
    rule_id: str
    group: str
    name: str
    expr: str
    for_duration: str
    severity: str
    summary: str
    runbook_url: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "group": self.group,
            "name": self.name,
            "expr": self.expr,
            "for_duration": self.for_duration,
            "severity": self.severity,
            "summary": self.summary,
            "runbook_url": self.runbook_url,
        }


# ---------------------------------------------------------------------------
# Canonical rule catalog (12 security + availability/perf/compliance fillers)
# ---------------------------------------------------------------------------

RULE_GROUPS: Tuple[str, ...] = ("security", "availability", "performance", "compliance")


_PRESET_RULES: Tuple[AlertRule, ...] = (
    # ---- security (12 canonical) -------------------------------------------
    AlertRule(
        rule_id="high-severity-finding-spike",
        group="security",
        name="High-Severity Finding Spike",
        expr="rate_findings_high_5m > 10",
        for_duration="5m",
        severity="critical",
        summary="High-severity finding rate exceeded 10/5m window.",
        runbook_url="https://runbooks.aldeci.io/findings/high-spike",
    ),
    AlertRule(
        rule_id="brain-pipeline-failure-rate",
        group="security",
        name="Brain Pipeline Failure Rate",
        expr="brain_pipeline_failures_total / brain_pipeline_runs_total > 0.05",
        for_duration="10m",
        severity="critical",
        summary="Brain Pipeline failure rate exceeded 5%.",
        runbook_url="https://runbooks.aldeci.io/brain/failure-rate",
    ),
    AlertRule(
        rule_id="scanner-error-rate",
        group="security",
        name="Scanner Error Rate Elevated",
        expr="scanner_errors_total / scanner_runs_total > 0.10",
        for_duration="15m",
        severity="warning",
        summary="Scanner error ratio above 10% across active scanners.",
        runbook_url="https://runbooks.aldeci.io/scanners/error-rate",
    ),
    AlertRule(
        rule_id="trustgraph-emit-failures",
        group="security",
        name="TrustGraph Emit Failures",
        expr="trustgraph_emit_failures_total > 25",
        for_duration="5m",
        severity="warning",
        summary="TrustGraph event-bus emit failures exceeded 25 in window.",
        runbook_url="https://runbooks.aldeci.io/trustgraph/emit-failures",
    ),
    AlertRule(
        rule_id="llm-consensus-disagreement-rate",
        group="security",
        name="LLM Consensus Disagreement Rate",
        expr="llm_consensus_disagreements_total / llm_consensus_runs_total > 0.30",
        for_duration="15m",
        severity="warning",
        summary="LLM council disagreement rate exceeded 30%.",
        runbook_url="https://runbooks.aldeci.io/llm/disagreement",
    ),
    AlertRule(
        rule_id="mttr-degradation",
        group="security",
        name="MTTR Degradation",
        expr="mttr_minutes_p95 > 240",
        for_duration="30m",
        severity="warning",
        summary="P95 MTTR exceeded 240 minutes (4h SLA).",
        runbook_url="https://runbooks.aldeci.io/sla/mttr",
    ),
    AlertRule(
        rule_id="finding-backlog-growth",
        group="security",
        name="Finding Backlog Growth",
        expr="findings_open_total - findings_open_total_24h_ago > 500",
        for_duration="1h",
        severity="warning",
        summary="Open finding backlog grew by >500 in 24h.",
        runbook_url="https://runbooks.aldeci.io/backlog/growth",
    ),
    AlertRule(
        rule_id="integration-down",
        group="security",
        name="Integration Down",
        expr="integration_up == 0",
        for_duration="5m",
        severity="critical",
        summary="A configured integration health probe reported down.",
        runbook_url="https://runbooks.aldeci.io/integrations/down",
    ),
    AlertRule(
        rule_id="webhook-dlq-overflow",
        group="security",
        name="Webhook DLQ Overflow",
        expr="webhook_dlq_depth > 1000",
        for_duration="5m",
        severity="critical",
        summary="Webhook dead-letter queue exceeded 1000 messages.",
        runbook_url="https://runbooks.aldeci.io/webhooks/dlq",
    ),
    AlertRule(
        rule_id="license-expiry-warning",
        group="security",
        name="License Expiry Warning",
        expr="license_days_remaining < 30",
        for_duration="1h",
        severity="warning",
        summary="License expires in fewer than 30 days.",
        runbook_url="https://runbooks.aldeci.io/license/expiry",
    ),
    AlertRule(
        rule_id="evidence-vault-fail",
        group="security",
        name="Evidence Vault Write Failure",
        expr="evidence_vault_write_failures_total > 0",
        for_duration="2m",
        severity="critical",
        summary="Quantum-safe evidence vault encountered a write failure.",
        runbook_url="https://runbooks.aldeci.io/evidence/vault-fail",
    ),
    AlertRule(
        rule_id="mfa-bypass-attempt",
        group="security",
        name="MFA Bypass Attempt",
        expr="mfa_bypass_attempts_total > 0",
        for_duration="1m",
        severity="critical",
        summary="One or more MFA bypass attempts detected.",
        runbook_url="https://runbooks.aldeci.io/identity/mfa-bypass",
    ),
    # ---- availability ------------------------------------------------------
    AlertRule(
        rule_id="api-error-rate",
        group="availability",
        name="API Error Rate Elevated",
        expr="api_5xx_total / api_requests_total > 0.02",
        for_duration="10m",
        severity="warning",
        summary="API 5xx error ratio above 2%.",
        runbook_url="https://runbooks.aldeci.io/availability/api-5xx",
    ),
    AlertRule(
        rule_id="db-connection-saturation",
        group="availability",
        name="DB Connection Pool Saturation",
        expr="db_connections_in_use / db_connections_max > 0.90",
        for_duration="5m",
        severity="warning",
        summary="DB connection pool above 90% utilization.",
        runbook_url="https://runbooks.aldeci.io/availability/db-pool",
    ),
    # ---- performance -------------------------------------------------------
    AlertRule(
        rule_id="api-latency-p99",
        group="performance",
        name="API Latency P99 Exceeded",
        expr="api_latency_p99_ms > 1500",
        for_duration="10m",
        severity="warning",
        summary="API P99 latency exceeded 1500ms.",
        runbook_url="https://runbooks.aldeci.io/performance/api-latency",
    ),
    AlertRule(
        rule_id="brain-pipeline-latency",
        group="performance",
        name="Brain Pipeline Latency",
        expr="brain_pipeline_duration_seconds_p95 > 60",
        for_duration="15m",
        severity="warning",
        summary="Brain Pipeline P95 duration exceeded 60s.",
        runbook_url="https://runbooks.aldeci.io/performance/brain-pipeline",
    ),
    # ---- compliance --------------------------------------------------------
    AlertRule(
        rule_id="compliance-control-failed",
        group="compliance",
        name="Compliance Control Failed",
        expr="compliance_control_failures_total > 0",
        for_duration="5m",
        severity="critical",
        summary="At least one compliance control transitioned to failed state.",
        runbook_url="https://runbooks.aldeci.io/compliance/control-failed",
    ),
    AlertRule(
        rule_id="audit-log-gap",
        group="compliance",
        name="Audit Log Gap Detected",
        expr="audit_log_gap_seconds > 300",
        for_duration="5m",
        severity="critical",
        summary="Audit log ingestion gap exceeded 300 seconds.",
        runbook_url="https://runbooks.aldeci.io/compliance/audit-gap",
    ),
)


# ---------------------------------------------------------------------------
# Safe PromQL-subset interpreter
# ---------------------------------------------------------------------------


class PromQLEvalError(Exception):
    """Raised when an expression uses PromQL features outside the safe subset."""


_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<NUMBER>\d+(?:\.\d+)?)"
    r"|(?P<IDENT>[A-Za-z_][A-Za-z0-9_:]*)"
    r"|(?P<OP>>=|<=|==|!=|>|<|\+|\-|\*|\/|\(|\))"
    r")"
)

_LOGICAL_KEYWORDS = {"and", "or", "unless"}


def _tokenize(expr: str) -> List[Tuple[str, str]]:
    tokens: List[Tuple[str, str]] = []
    pos = 0
    n = len(expr)
    while pos < n:
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            # Skip pure whitespace
            if expr[pos].isspace():
                pos += 1
                continue
            raise PromQLEvalError(f"Unexpected character at pos {pos}: {expr[pos]!r}")
        kind = m.lastgroup or ""
        value = m.group(kind)
        # treat reserved logical keywords distinctly
        if kind == "IDENT" and value in _LOGICAL_KEYWORDS:
            tokens.append(("LOGICAL", value))
        else:
            tokens.append((kind, value))
        pos = m.end()
    tokens.append(("EOF", ""))
    return tokens


@dataclass
class _Parser:
    tokens: List[Tuple[str, str]]
    metrics: Dict[str, float]
    pos: int = 0

    # Lookahead helpers
    def peek(self) -> Tuple[str, str]:
        return self.tokens[self.pos]

    def consume(self) -> Tuple[str, str]:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def match(self, kind: str, value: Optional[str] = None) -> bool:
        k, v = self.peek()
        if k != kind:
            return False
        if value is not None and v != value:
            return False
        self.consume()
        return True

    # Grammar:
    #   expr   := orexpr
    #   orexpr := andexpr ( ('or'|'unless') andexpr )*
    #   andexpr:= cmpexpr ( 'and' cmpexpr )*
    #   cmpexpr:= addexpr ( (>|<|>=|<=|==|!=) addexpr )?
    #   addexpr:= mulexpr ( ('+'|'-') mulexpr )*
    #   mulexpr:= primary ( ('*'|'/') primary )*
    #   primary:= NUMBER | IDENT | '(' expr ')'

    def parse(self) -> Any:
        result = self._or_expr()
        if self.peek()[0] != "EOF":
            raise PromQLEvalError(f"Unexpected trailing token: {self.peek()!r}")
        return result

    def _or_expr(self) -> Any:
        left = self._and_expr()
        while True:
            k, v = self.peek()
            if k == "LOGICAL" and v in ("or", "unless"):
                op = v
                self.consume()
                right = self._and_expr()
                left_b = bool(left)
                right_b = bool(right)
                if op == "or":
                    left = left_b or right_b
                else:  # unless
                    left = left_b and not right_b
            else:
                break
        return left

    def _and_expr(self) -> Any:
        left = self._cmp_expr()
        while True:
            k, v = self.peek()
            if k == "LOGICAL" and v == "and":
                self.consume()
                right = self._cmp_expr()
                left = bool(left) and bool(right)
            else:
                break
        return left

    def _cmp_expr(self) -> Any:
        left = self._add_expr()
        k, v = self.peek()
        if k == "OP" and v in (">", "<", ">=", "<=", "==", "!="):
            op = v
            self.consume()
            right = self._add_expr()
            try:
                lf = float(left)
                rf = float(right)
            except (TypeError, ValueError) as exc:
                raise PromQLEvalError(
                    f"comparison requires numeric operands, got {left!r} {op} {right!r}"
                ) from exc
            if op == ">":
                return lf > rf
            if op == "<":
                return lf < rf
            if op == ">=":
                return lf >= rf
            if op == "<=":
                return lf <= rf
            if op == "==":
                return lf == rf
            if op == "!=":
                return lf != rf
        return left

    def _add_expr(self) -> Any:
        left = self._mul_expr()
        while True:
            k, v = self.peek()
            if k == "OP" and v in ("+", "-"):
                op = v
                self.consume()
                right = self._mul_expr()
                try:
                    left = float(left) + float(right) if op == "+" else float(left) - float(right)
                except (TypeError, ValueError) as exc:
                    raise PromQLEvalError(
                        f"arithmetic requires numeric operands ({left!r} {op} {right!r})"
                    ) from exc
            else:
                break
        return left

    def _mul_expr(self) -> Any:
        left = self._primary()
        while True:
            k, v = self.peek()
            if k == "OP" and v in ("*", "/"):
                op = v
                self.consume()
                right = self._primary()
                try:
                    if op == "*":
                        left = float(left) * float(right)
                    else:
                        rf = float(right)
                        if rf == 0:
                            # PromQL returns +Inf / NaN; we coerce to 0 to avoid div-by-zero crash
                            left = 0.0
                        else:
                            left = float(left) / rf
                except (TypeError, ValueError) as exc:
                    raise PromQLEvalError(
                        f"arithmetic requires numeric operands ({left!r} {op} {right!r})"
                    ) from exc
            else:
                break
        return left

    def _primary(self) -> Any:
        k, v = self.peek()
        if k == "NUMBER":
            self.consume()
            return float(v)
        if k == "IDENT":
            self.consume()
            # any structural PromQL features such as label selectors '{...}',
            # offsets '@', or function calls '(' immediately following an IDENT
            # are unsupported in the safe subset
            nk, nv = self.peek()
            if nk == "OP" and nv == "(":
                raise PromQLEvalError(f"function calls not supported in safe subset: {v}(")
            if v not in self.metrics:
                # Missing metric defaults to 0 (Prometheus 'absent' semantics)
                return 0.0
            return float(self.metrics[v])
        if k == "OP" and v == "(":
            self.consume()
            inner = self._or_expr()
            if not self.match("OP", ")"):
                raise PromQLEvalError("missing closing ')'")
            return inner
        raise PromQLEvalError(f"unexpected token {self.peek()!r}")


def evaluate_promql(expr: str, sample_metrics: Dict[str, float]) -> Tuple[str, str]:
    """Evaluate a PromQL-subset expression against sample_metrics.

    Returns (evaluation_result, evaluated_expr) where evaluation_result is one of
        firing | inactive | pending | degraded
    'degraded' is used when the expression uses unsupported PromQL features.
    """

    if not expr or not expr.strip():
        return ("inactive", expr or "")

    try:
        tokens = _tokenize(expr)
        parser = _Parser(tokens=tokens, metrics={k: float(v) for k, v in (sample_metrics or {}).items()})
        result = parser.parse()
    except PromQLEvalError as exc:
        logger.info("PromQL eval degraded: expr=%r reason=%s", expr, exc)
        return ("degraded", expr)
    except (TypeError, ValueError) as exc:
        logger.info("PromQL eval failed: expr=%r reason=%s", expr, exc)
        return ("degraded", expr)

    # Coerce numeric to truthy: in PromQL, an alert fires when the vector is non-empty.
    # In our safe subset we treat boolean True or any non-zero numeric as firing.
    if isinstance(result, bool):
        firing = result
    else:
        try:
            firing = float(result) != 0.0
        except (TypeError, ValueError):
            firing = bool(result)

    return ("firing" if firing else "inactive", expr)


# ---------------------------------------------------------------------------
# Engine + singleton
# ---------------------------------------------------------------------------


@dataclass
class PrometheusAlertsEngine:
    rules: Tuple[AlertRule, ...] = field(default_factory=lambda: _PRESET_RULES)

    def list_rules(self, group: Optional[str] = None) -> List[AlertRule]:
        if group is None:
            return list(self.rules)
        return [r for r in self.rules if r.group == group]

    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        rid = (rule_id or "").strip()
        for r in self.rules:
            if r.rule_id == rid:
                return r
        return None

    def list_groups(self) -> List[Dict[str, Any]]:
        groups: Dict[str, int] = {g: 0 for g in RULE_GROUPS}
        for r in self.rules:
            groups[r.group] = groups.get(r.group, 0) + 1
        return [{"group": g, "rule_count": c} for g, c in groups.items()]

    def evaluate(
        self,
        rule_id: str,
        sample_metrics: Dict[str, float],
    ) -> Dict[str, Any]:
        rule = self.get_rule(rule_id)
        if rule is None:
            raise KeyError(rule_id)
        result, expr = evaluate_promql(rule.expr, sample_metrics or {})
        return {
            "rule_id": rule.rule_id,
            "evaluation_result": result,
            "evaluated_expr": expr,
            "sample_metrics": dict(sample_metrics or {}),
        }

    def status(self) -> str:
        return "ok" if self.rules else "empty"


_engine_singleton: Optional[PrometheusAlertsEngine] = None


def get_prometheus_alerts_engine() -> PrometheusAlertsEngine:
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = PrometheusAlertsEngine()
    return _engine_singleton


__all__ = [
    "AlertRule",
    "PromQLEvalError",
    "PrometheusAlertsEngine",
    "RULE_GROUPS",
    "evaluate_promql",
    "get_prometheus_alerts_engine",
]
