"""Security Query Language (SQL) Engine — ALDECI GAP-024.

RQL-style structured DSL over cloud, audit, network, IAM, and asset data.
Hand-rolled lexer, parser, planner, and executor (stdlib only).

Example query:

    FROM aws.ec2.instance
    WHERE public = true AND tag.env = 'prod'
    WITH findings.critical > 0
    RETURN asset_id, blast_radius

Providers:
  - 'memory'  -> dict-of-rows (fixtures / tests)
  - 'sqlite'  -> maps entities to existing tables (security_findings, cspm_findings,
                 identity_risk, asset_criticality, network_flows)

Compliance: NIST SP 800-53 AU-6, SOC 2 CC7.2, ISO 27001 A.12.4
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except Exception:  # pragma: no cover - best-effort
    _get_tg_bus = None  # type: ignore

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_query_language.db"
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SQLSyntaxError(ValueError):
    """Raised for lexer/parser errors."""


class SQLTypeError(ValueError):
    """Raised when a filter references an unknown field or compares mismatched types."""


class SQLPlanError(RuntimeError):
    """Raised when the planner cannot produce a valid execution plan."""


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

_KEYWORDS = {"FROM", "WHERE", "WITH", "RETURN", "AND", "OR", "NOT", "IN", "TRUE", "FALSE", "NULL"}
_OPERATORS = {"=", "!=", "<", ">", "<=", ">="}


@dataclass
class Token:
    kind: str      # IDENT | NUMBER | STRING | OP | LPAREN | RPAREN | COMMA | KW | EOF
    value: Any
    pos: int

    def __repr__(self) -> str:  # pragma: no cover - debug
        return f"Token({self.kind}, {self.value!r}, {self.pos})"


class TokenStream:
    """Lexer producing a stream of Token objects."""

    def __init__(self, src: str) -> None:
        if not isinstance(src, str):
            raise SQLSyntaxError("query must be a string")
        self.src = src
        self.pos = 0
        self._tokens: List[Token] = []
        self._idx = 0
        self._tokenize()

    # ------------------------------------------------------------------ helpers
    def _peek(self, offset: int = 0) -> str:
        p = self.pos + offset
        return self.src[p] if p < len(self.src) else ""

    def _advance(self) -> str:
        ch = self._peek()
        self.pos += 1
        return ch

    # ------------------------------------------------------------------ tokenize
    def _tokenize(self) -> None:
        src = self.src
        while self.pos < len(src):
            ch = self._peek()
            if ch.isspace():
                self.pos += 1
                continue
            if ch == "(":
                self._tokens.append(Token("LPAREN", ch, self.pos))
                self.pos += 1
                continue
            if ch == ")":
                self._tokens.append(Token("RPAREN", ch, self.pos))
                self.pos += 1
                continue
            if ch == ",":
                self._tokens.append(Token("COMMA", ch, self.pos))
                self.pos += 1
                continue
            if ch in "<>!=":
                start = self.pos
                op = self._advance()
                if self._peek() == "=":
                    op += self._advance()
                if op not in _OPERATORS:
                    raise SQLSyntaxError(f"unknown operator {op!r} at {start}")
                self._tokens.append(Token("OP", op, start))
                continue
            if ch == "=":
                self._tokens.append(Token("OP", "=", self.pos))
                self.pos += 1
                continue
            if ch in ("'", '"'):
                self._tokens.append(self._read_string(ch))
                continue
            if ch.isdigit() or (ch == "-" and self._peek(1).isdigit()):
                self._tokens.append(self._read_number())
                continue
            if ch.isalpha() or ch == "_":
                self._tokens.append(self._read_ident())
                continue
            raise SQLSyntaxError(f"unexpected character {ch!r} at position {self.pos}")
        self._tokens.append(Token("EOF", None, self.pos))

    def _read_string(self, quote: str) -> Token:
        start = self.pos
        self.pos += 1  # consume opening quote
        buf: List[str] = []
        while self.pos < len(self.src):
            ch = self._peek()
            if ch == "\\" and self.pos + 1 < len(self.src):
                nxt = self.src[self.pos + 1]
                esc = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"'}.get(nxt, nxt)
                buf.append(esc)
                self.pos += 2
                continue
            if ch == quote:
                self.pos += 1
                return Token("STRING", "".join(buf), start)
            buf.append(ch)
            self.pos += 1
        raise SQLSyntaxError(f"unterminated string starting at {start}")

    def _read_number(self) -> Token:
        start = self.pos
        if self._peek() == "-":
            self.pos += 1
        while self._peek().isdigit():
            self.pos += 1
        is_float = False
        if self._peek() == "." and self._peek(1).isdigit():
            is_float = True
            self.pos += 1
            while self._peek().isdigit():
                self.pos += 1
        raw = self.src[start:self.pos]
        value: Any = float(raw) if is_float else int(raw)
        return Token("NUMBER", value, start)

    def _read_ident(self) -> Token:
        start = self.pos
        while self.pos < len(self.src):
            ch = self._peek()
            if ch.isalnum() or ch in ("_", ".", "-"):
                self.pos += 1
            else:
                break
        raw = self.src[start:self.pos]
        upper = raw.upper()
        if upper in _KEYWORDS:
            if upper == "TRUE":
                return Token("BOOL", True, start)
            if upper == "FALSE":
                return Token("BOOL", False, start)
            if upper == "NULL":
                return Token("NULL", None, start)
            return Token("KW", upper, start)
        return Token("IDENT", raw, start)

    # ------------------------------------------------------------------ stream
    def peek(self, offset: int = 0) -> Token:
        idx = self._idx + offset
        if idx >= len(self._tokens):
            return self._tokens[-1]
        return self._tokens[idx]

    def next(self) -> Token:
        tok = self._tokens[self._idx]
        if tok.kind != "EOF":
            self._idx += 1
        return tok

    def expect(self, kind: str, value: Optional[Any] = None) -> Token:
        tok = self.peek()
        if tok.kind != kind or (value is not None and tok.value != value):
            exp = f"{kind}{'=' + str(value) if value is not None else ''}"
            raise SQLSyntaxError(f"expected {exp} at position {tok.pos}, got {tok.kind}={tok.value!r}")
        return self.next()

    def eof(self) -> bool:
        return self.peek().kind == "EOF"

    def as_list(self) -> List[Token]:
        return list(self._tokens)


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------

@dataclass
class FilterNode:
    lhs: str
    op: str
    rhs: Any

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "filter", "lhs": self.lhs, "op": self.op, "rhs": self.rhs}


@dataclass
class LogicalNode:
    op: str                                # AND / OR / NOT
    children: List[Any] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "logical",
            "op": self.op,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class QueryNode:
    from_path: str
    filters: Optional[Any]                  # FilterNode or LogicalNode (or None)
    with_clause: Optional[Any]              # same as filters (or None)
    return_fields: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "query",
            "from": self.from_path,
            "filters": self.filters.to_dict() if self.filters else None,
            "with": self.with_clause.to_dict() if self.with_clause else None,
            "return": list(self.return_fields),
        }


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class Parser:
    """Recursive-descent parser producing a QueryNode."""

    def __init__(self, tokens: TokenStream) -> None:
        self.tokens = tokens

    # ------------------------------------------------------------------ entry
    def parse(self) -> QueryNode:
        self.tokens.expect("KW", "FROM")
        from_tok = self.tokens.expect("IDENT")
        filters: Optional[Any] = None
        with_clause: Optional[Any] = None

        if self.tokens.peek().kind == "KW" and self.tokens.peek().value == "WHERE":
            self.tokens.next()
            filters = self._parse_expression()

        if self.tokens.peek().kind == "KW" and self.tokens.peek().value == "WITH":
            self.tokens.next()
            with_clause = self._parse_expression()

        self.tokens.expect("KW", "RETURN")
        return_fields = self._parse_return_list()

        if not self.tokens.eof():
            tok = self.tokens.peek()
            raise SQLSyntaxError(f"unexpected trailing token {tok.kind}={tok.value!r} at {tok.pos}")

        return QueryNode(
            from_path=from_tok.value,
            filters=filters,
            with_clause=with_clause,
            return_fields=return_fields,
        )

    # ------------------------------------------------------------------ RETURN
    def _parse_return_list(self) -> List[str]:
        fields: List[str] = []
        tok = self.tokens.expect("IDENT")
        fields.append(tok.value)
        while self.tokens.peek().kind == "COMMA":
            self.tokens.next()
            tok = self.tokens.expect("IDENT")
            fields.append(tok.value)
        if not fields:
            raise SQLSyntaxError("RETURN clause requires at least one field")
        return fields

    # ------------------------------------------------------------------ expression
    # expr := or_expr
    # or_expr := and_expr (OR and_expr)*
    # and_expr := not_expr (AND not_expr)*
    # not_expr := NOT not_expr | primary
    # primary := '(' expr ')' | comparison
    # comparison := IDENT OP literal | IDENT IN '(' literal_list ')'

    def _parse_expression(self) -> Any:
        return self._parse_or()

    def _parse_or(self) -> Any:
        left = self._parse_and()
        while self.tokens.peek().kind == "KW" and self.tokens.peek().value == "OR":
            self.tokens.next()
            right = self._parse_and()
            if isinstance(left, LogicalNode) and left.op == "OR":
                left.children.append(right)
            else:
                left = LogicalNode("OR", [left, right])
        return left

    def _parse_and(self) -> Any:
        left = self._parse_not()
        while self.tokens.peek().kind == "KW" and self.tokens.peek().value == "AND":
            self.tokens.next()
            right = self._parse_not()
            if isinstance(left, LogicalNode) and left.op == "AND":
                left.children.append(right)
            else:
                left = LogicalNode("AND", [left, right])
        return left

    def _parse_not(self) -> Any:
        if self.tokens.peek().kind == "KW" and self.tokens.peek().value == "NOT":
            self.tokens.next()
            child = self._parse_not()
            return LogicalNode("NOT", [child])
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        tok = self.tokens.peek()
        if tok.kind == "LPAREN":
            self.tokens.next()
            inner = self._parse_expression()
            self.tokens.expect("RPAREN")
            return inner
        return self._parse_comparison()

    def _parse_comparison(self) -> FilterNode:
        lhs = self.tokens.expect("IDENT").value
        tok = self.tokens.peek()
        if tok.kind == "KW" and tok.value == "IN":
            self.tokens.next()
            self.tokens.expect("LPAREN")
            values: List[Any] = [self._parse_literal()]
            while self.tokens.peek().kind == "COMMA":
                self.tokens.next()
                values.append(self._parse_literal())
            self.tokens.expect("RPAREN")
            return FilterNode(lhs=lhs, op="IN", rhs=values)
        if tok.kind != "OP":
            raise SQLSyntaxError(
                f"expected comparison operator after identifier {lhs!r} at position {tok.pos}"
            )
        op = self.tokens.next().value
        rhs = self._parse_literal()
        return FilterNode(lhs=lhs, op=op, rhs=rhs)

    def _parse_literal(self) -> Any:
        tok = self.tokens.peek()
        if tok.kind in ("STRING", "NUMBER", "BOOL"):
            self.tokens.next()
            return tok.value
        if tok.kind == "NULL":
            self.tokens.next()
            return None
        raise SQLSyntaxError(f"expected literal at position {tok.pos}, got {tok.kind}")


# ---------------------------------------------------------------------------
# Schema registry — 20 entity types, 10 fields each
# ---------------------------------------------------------------------------

def _default_schema() -> Dict[str, Dict[str, str]]:
    """Seed 20 core entity types, each with ~10 typed fields."""
    return {
        "asset": {
            "asset_id": "string", "name": "string", "type": "string",
            "owner": "string", "severity": "string", "criticality": "string",
            "environment": "string", "blast_radius": "number",
            "created_at": "string", "tags": "string",
        },
        "finding": {
            "finding_id": "string", "asset_id": "string", "severity": "string",
            "status": "string", "cve": "string", "cvss": "number",
            "epss": "number", "kev": "bool", "created_at": "string",
            "title": "string",
        },
        "identity": {
            "identity_id": "string", "name": "string", "type": "string",
            "last_login": "string", "mfa_enabled": "bool", "risk_score": "number",
            "department": "string", "active": "bool", "created_at": "string",
            "privileged": "bool",
        },
        "cloud_resource": {
            "resource_id": "string", "provider": "string", "region": "string",
            "type": "string", "public": "bool", "encrypted": "bool",
            "owner": "string", "cost_month_usd": "number",
            "created_at": "string", "tag.env": "string",
        },
        "network_flow": {
            "flow_id": "string", "src_ip": "string", "dst_ip": "string",
            "src_port": "number", "dst_port": "number", "protocol": "string",
            "bytes": "number", "packets": "number", "timestamp": "string",
            "action": "string",
        },
        "aws.ec2.instance": {
            "asset_id": "string", "instance_id": "string", "public": "bool",
            "region": "string", "state": "string", "vpc_id": "string",
            "tag.env": "string", "tag.owner": "string",
            "blast_radius": "number", "created_at": "string",
        },
        "aws.s3.bucket": {
            "asset_id": "string", "bucket_name": "string", "public": "bool",
            "encrypted": "bool", "versioning": "bool", "region": "string",
            "created_at": "string", "tag.env": "string",
            "size_gb": "number", "blast_radius": "number",
        },
        "aws.iam.user": {
            "identity_id": "string", "user_name": "string", "mfa_enabled": "bool",
            "access_key_age_days": "number", "last_login": "string",
            "privileged": "bool", "groups": "string", "policies": "string",
            "created_at": "string", "risk_score": "number",
        },
        "aws.iam.role": {
            "identity_id": "string", "role_name": "string", "privileged": "bool",
            "trusted_entities": "string", "last_used": "string",
            "created_at": "string", "policies": "string",
            "risk_score": "number", "max_session": "number", "path": "string",
        },
        "aws.rds.instance": {
            "asset_id": "string", "db_identifier": "string", "engine": "string",
            "public": "bool", "encrypted": "bool", "region": "string",
            "backup_retention": "number", "created_at": "string",
            "tag.env": "string", "blast_radius": "number",
        },
        "azure.vm.instance": {
            "asset_id": "string", "vm_name": "string", "public": "bool",
            "region": "string", "state": "string", "subscription_id": "string",
            "tag.env": "string", "tag.owner": "string",
            "blast_radius": "number", "created_at": "string",
        },
        "azure.storage.account": {
            "asset_id": "string", "name": "string", "public": "bool",
            "encrypted": "bool", "region": "string", "tier": "string",
            "created_at": "string", "tag.env": "string",
            "size_gb": "number", "blast_radius": "number",
        },
        "gcp.compute.instance": {
            "asset_id": "string", "instance_name": "string", "public": "bool",
            "region": "string", "state": "string", "project_id": "string",
            "tag.env": "string", "tag.owner": "string",
            "blast_radius": "number", "created_at": "string",
        },
        "gcp.storage.bucket": {
            "asset_id": "string", "bucket_name": "string", "public": "bool",
            "encrypted": "bool", "location": "string", "storage_class": "string",
            "created_at": "string", "tag.env": "string",
            "size_gb": "number", "blast_radius": "number",
        },
        "k8s.pod": {
            "asset_id": "string", "pod_name": "string", "namespace": "string",
            "node": "string", "privileged": "bool", "image": "string",
            "status": "string", "host_network": "bool",
            "created_at": "string", "blast_radius": "number",
        },
        "k8s.service": {
            "asset_id": "string", "service_name": "string", "namespace": "string",
            "type": "string", "public": "bool", "cluster_ip": "string",
            "selector": "string", "ports": "string",
            "created_at": "string", "blast_radius": "number",
        },
        "container.image": {
            "image_id": "string", "repo": "string", "tag": "string",
            "digest": "string", "size_mb": "number",
            "critical_vulns": "number", "high_vulns": "number",
            "signed": "bool", "scanned_at": "string", "registry": "string",
        },
        "vulnerability": {
            "cve": "string", "cvss": "number", "epss": "number",
            "kev": "bool", "severity": "string", "published": "string",
            "vendor": "string", "product": "string",
            "exploit_available": "bool", "patched": "bool",
        },
        "audit_event": {
            "event_id": "string", "actor": "string", "action": "string",
            "resource": "string", "source_ip": "string", "result": "string",
            "timestamp": "string", "user_agent": "string",
            "risk_score": "number", "success": "bool",
        },
        "network_exposure": {
            "asset_id": "string", "exposure_id": "string", "port": "number",
            "protocol": "string", "service": "string", "public": "bool",
            "cve_count": "number", "critical_count": "number",
            "last_seen": "string", "blast_radius": "number",
        },
    }


class SchemaRegistry:
    """Registry of entity types and typed fields."""

    def __init__(self, schema: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        self._schema: Dict[str, Dict[str, str]] = schema or _default_schema()

    def has_entity(self, path: str) -> bool:
        return path in self._schema

    def get_fields(self, path: str) -> Dict[str, str]:
        if not self.has_entity(path):
            raise SQLTypeError(f"unknown entity {path!r}")
        return dict(self._schema[path])

    def get_field_type(self, path: str, field_name: str) -> str:
        fields = self._schema.get(path)
        if fields is None:
            raise SQLTypeError(f"unknown entity {path!r}")
        # Allow nested fields (e.g. findings.critical, tag.env)
        if field_name in fields:
            return fields[field_name]
        # Cross-entity reference: 'findings.critical' and similar counts are numbers
        prefix, _, rest = field_name.partition(".")
        if rest and prefix in {
            "findings", "vulns", "vulnerabilities", "count", "counts",
        }:
            return "number"
        if rest and prefix == "tag":
            return "string"
        raise SQLTypeError(f"unknown field {field_name!r} on entity {path!r}")

    def entities(self) -> List[str]:
        return sorted(self._schema.keys())

    def to_dict(self) -> Dict[str, Dict[str, str]]:
        return {k: dict(v) for k, v in self._schema.items()}


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

@dataclass
class CompiledQuery:
    dsl: str
    ast: QueryNode
    entity: str
    return_fields: List[str]
    plan_json: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dsl": self.dsl,
            "entity": self.entity,
            "return_fields": list(self.return_fields),
            "plan": self.plan_json,
        }


class QueryPlanner:
    """Validates AST against the SchemaRegistry and returns a CompiledQuery."""

    _NUMERIC_OPS = {"<", ">", "<=", ">=", "=", "!="}
    _STRING_OPS = {"=", "!=", "IN"}
    _BOOL_OPS = {"=", "!="}

    def __init__(self, schema: SchemaRegistry) -> None:
        self.schema = schema

    def plan(self, ast: QueryNode, dsl: str) -> CompiledQuery:
        if not self.schema.has_entity(ast.from_path):
            raise SQLTypeError(f"unknown entity {ast.from_path!r}")
        for field_name in ast.return_fields:
            # RETURN field must type-check (we allow cross-entity prefixes)
            self.schema.get_field_type(ast.from_path, field_name)
        if ast.filters is not None:
            self._validate_expr(ast.from_path, ast.filters)
        if ast.with_clause is not None:
            self._validate_expr(ast.from_path, ast.with_clause)
        plan_json = ast.to_dict()
        return CompiledQuery(
            dsl=dsl,
            ast=ast,
            entity=ast.from_path,
            return_fields=list(ast.return_fields),
            plan_json=plan_json,
        )

    def _validate_expr(self, entity: str, node: Any) -> None:
        if isinstance(node, LogicalNode):
            for child in node.children:
                self._validate_expr(entity, child)
            return
        if isinstance(node, FilterNode):
            field_type = self.schema.get_field_type(entity, node.lhs)
            self._check_type(node, field_type)
            return
        raise SQLPlanError(f"unknown AST node type: {type(node).__name__}")

    def _check_type(self, node: FilterNode, field_type: str) -> None:
        op = node.op
        rhs = node.rhs
        if field_type == "number":
            if op not in self._NUMERIC_OPS and op != "IN":
                raise SQLTypeError(f"operator {op!r} not valid for numeric field {node.lhs!r}")
            if op == "IN":
                for v in rhs:
                    if not isinstance(v, (int, float)):
                        raise SQLTypeError(f"IN list must contain numbers for {node.lhs!r}")
            else:
                if not isinstance(rhs, (int, float)):
                    raise SQLTypeError(
                        f"field {node.lhs!r} is numeric but rhs is {type(rhs).__name__}"
                    )
        elif field_type == "string":
            if op not in self._STRING_OPS:
                raise SQLTypeError(f"operator {op!r} not valid for string field {node.lhs!r}")
            if op == "IN":
                for v in rhs:
                    if not isinstance(v, str):
                        raise SQLTypeError(f"IN list must contain strings for {node.lhs!r}")
            elif not isinstance(rhs, str):
                raise SQLTypeError(
                    f"field {node.lhs!r} is string but rhs is {type(rhs).__name__}"
                )
        elif field_type == "bool":
            if op not in self._BOOL_OPS:
                raise SQLTypeError(f"operator {op!r} not valid for bool field {node.lhs!r}")
            if not isinstance(rhs, bool):
                raise SQLTypeError(f"field {node.lhs!r} is bool but rhs is {type(rhs).__name__}")


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

class InMemoryProvider:
    """Dict-of-rows provider for fixtures + testing."""

    def __init__(self, data: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> None:
        self._data: Dict[str, List[Dict[str, Any]]] = {
            k: [dict(r) for r in v] for k, v in (data or {}).items()
        }

    def set_rows(self, entity: str, rows: Sequence[Mapping[str, Any]]) -> None:
        self._data[entity] = [dict(r) for r in rows]

    def rows(self, entity: str) -> List[Dict[str, Any]]:
        return list(self._data.get(entity, []))


class SqliteProvider:
    """Maps entities to existing ALDECI SQLite tables. Falls back to empty rowsets
    when the sibling table / column is unavailable — never raises for missing
    data, so queries degrade gracefully in fresh installs."""

    _DEFAULT_MAP: Dict[str, Tuple[str, str]] = {
        # entity -> (db_filename, table)
        "asset": ("security_findings.db", "findings"),
        "finding": ("security_findings.db", "findings"),
        "vulnerability": ("security_findings.db", "findings"),
        "cloud_resource": ("cloud_resource_inventory.db", "cloud_resources"),
        "aws.ec2.instance": ("cloud_resource_inventory.db", "cloud_resources"),
        "aws.s3.bucket": ("cspm_findings.db", "findings"),
        "aws.iam.user": ("identity_risk.db", "identities"),
        "aws.iam.role": ("identity_risk.db", "identities"),
        "aws.rds.instance": ("cloud_resource_inventory.db", "cloud_resources"),
        "azure.vm.instance": ("cloud_resource_inventory.db", "cloud_resources"),
        "azure.storage.account": ("cspm_findings.db", "findings"),
        "gcp.compute.instance": ("cloud_resource_inventory.db", "cloud_resources"),
        "gcp.storage.bucket": ("cspm_findings.db", "findings"),
        "identity": ("identity_risk.db", "identities"),
        "audit_event": ("audit_trail.db", "audit_events"),
        "network_flow": ("network_monitoring.db", "flows"),
        "network_exposure": ("attack_surface.db", "exposures"),
        "k8s.pod": ("kubernetes_security.db", "findings"),
        "k8s.service": ("kubernetes_security.db", "findings"),
        "container.image": ("container_registry_security.db", "images"),
    }

    def __init__(self, data_dir: Optional[str] = None) -> None:
        self._data_dir = Path(data_dir or Path(_DEFAULT_DB).parent)

    def rows(self, entity: str, org_id: str) -> List[Dict[str, Any]]:
        if entity not in self._DEFAULT_MAP:
            return []
        db_file, table = self._DEFAULT_MAP[entity]
        db_path = self._data_dir / db_file
        if not db_path.exists():
            return []
        try:
            con = sqlite3.connect(str(db_path), timeout=5.0)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            # Discover which columns exist; filter by org_id if present.
            # table name is validated against _DEFAULT_MAP allowlist before this point (line 720).
            cur.execute(f"PRAGMA table_info({table})")  # nosec B608 — table from internal allowlist only
            cols = [r["name"] for r in cur.fetchall()]
            if not cols:
                con.close()
                return []
            if "org_id" in cols:
                cur.execute(f"SELECT * FROM {table} WHERE org_id = ? LIMIT 10000", (org_id,))  # nosec B608 — table from internal allowlist only
            else:
                cur.execute(f"SELECT * FROM {table} LIMIT 10000")  # nosec B608 — table from internal allowlist only
            rows = [dict(r) for r in cur.fetchall()]
            con.close()
            return rows
        except sqlite3.Error:
            return []


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------

class QueryExecutor:
    """Evaluates a CompiledQuery against a provider, returning projected rows."""

    def __init__(
        self,
        memory_provider: Optional[InMemoryProvider] = None,
        sqlite_provider: Optional[SqliteProvider] = None,
    ) -> None:
        self.memory = memory_provider or InMemoryProvider()
        self.sqlite = sqlite_provider or SqliteProvider()

    def execute(self, compiled: CompiledQuery, org_id: str, provider: str = "memory") -> Dict[str, Any]:
        start = time.perf_counter()
        if provider == "memory":
            raw_rows = self.memory.rows(compiled.entity)
        elif provider == "sqlite":
            raw_rows = self.sqlite.rows(compiled.entity, org_id)
        else:
            raise SQLPlanError(f"unknown provider {provider!r}")
        filtered: List[Dict[str, Any]] = []
        for row in raw_rows:
            if compiled.ast.filters is not None and not self._eval(compiled.ast.filters, row):
                continue
            if compiled.ast.with_clause is not None and not self._eval(compiled.ast.with_clause, row):
                continue
            filtered.append(row)
        projected = [
            {f: self._extract(row, f) for f in compiled.return_fields}
            for row in filtered
        ]
        duration_ms = int((time.perf_counter() - start) * 1000)
        return {
            "rows": projected,
            "row_count": len(projected),
            "duration_ms": duration_ms,
            "provider": provider,
        }

    # ------------------------------------------------------------------ helpers
    def _eval(self, node: Any, row: Mapping[str, Any]) -> bool:
        if isinstance(node, LogicalNode):
            if node.op == "AND":
                return all(self._eval(c, row) for c in node.children)
            if node.op == "OR":
                return any(self._eval(c, row) for c in node.children)
            if node.op == "NOT":
                return not self._eval(node.children[0], row)
            raise SQLPlanError(f"unknown logical op {node.op!r}")
        if isinstance(node, FilterNode):
            lhs = self._extract(row, node.lhs)
            rhs = node.rhs
            op = node.op
            try:
                if op == "=":
                    return lhs == rhs
                if op == "!=":
                    return lhs != rhs
                if op == "<":
                    return lhs is not None and lhs < rhs
                if op == ">":
                    return lhs is not None and lhs > rhs
                if op == "<=":
                    return lhs is not None and lhs <= rhs
                if op == ">=":
                    return lhs is not None and lhs >= rhs
                if op == "IN":
                    return lhs in rhs
            except TypeError:
                return False
        raise SQLPlanError(f"cannot evaluate node {type(node).__name__}")

    @staticmethod
    def _extract(row: Mapping[str, Any], name: str) -> Any:
        if name in row:
            return row[name]
        # Support dotted-path access (e.g. findings.critical, tag.env)
        cur: Any = row
        for part in name.split("."):
            if isinstance(cur, Mapping) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur


# ---------------------------------------------------------------------------
# Engine — public façade with persistence
# ---------------------------------------------------------------------------

class SecurityQueryLanguageEngine:
    """Public façade: compile / execute / save / list / stats.

    Thread-safe via RLock. Multi-tenant via org_id on every row.
    WAL journaling enabled for concurrent reads.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        schema: Optional[SchemaRegistry] = None,
        memory_provider: Optional[InMemoryProvider] = None,
    ) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self.schema = schema or SchemaRegistry()
        self.planner = QueryPlanner(self.schema)
        self.executor = QueryExecutor(memory_provider=memory_provider)
        self.memory_provider = self.executor.memory
        self.ensure_schema()
        self._emit("engine.init", {"db_path": db_path})

    # ------------------------------------------------------------------ schema
    def ensure_schema(self) -> None:
        with self._lock:
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
            con = self._connect()
            cur = con.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS saved_queries (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    dsl_text TEXT NOT NULL,
                    compiled_plan_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(org_id, name)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS query_history (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    query_id TEXT,
                    dsl_text TEXT NOT NULL,
                    ran_at TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    row_count INTEGER NOT NULL,
                    result_hash TEXT NOT NULL
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_saved_org ON saved_queries(org_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hist_org ON query_history(org_id)")
            con.commit()
            con.close()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self._db_path, timeout=10.0)
        con.row_factory = sqlite3.Row
        return con

    # ------------------------------------------------------------------ compile
    def compile_query(self, dsl: str) -> CompiledQuery:
        if not isinstance(dsl, str) or not dsl.strip():
            raise SQLSyntaxError("query cannot be empty")
        tokens = TokenStream(dsl)
        parser = Parser(tokens)
        ast = parser.parse()
        return self.planner.plan(ast, dsl)

    # ------------------------------------------------------------------ execute
    def execute_query(
        self,
        org_id: str,
        dsl: str,
        provider: str = "memory",
        query_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id is required")
        compiled = self.compile_query(dsl)
        result = self.executor.execute(compiled, org_id=org_id, provider=provider)
        with self._lock:
            con = self._connect()
            cur = con.cursor()
            result_hash = hashlib.sha256(
                json.dumps(result["rows"], sort_keys=True, default=str).encode()
            ).hexdigest()
            cur.execute(
                """
                INSERT INTO query_history (
                    id, org_id, query_id, dsl_text, ran_at,
                    duration_ms, row_count, result_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    org_id,
                    query_id,
                    dsl,
                    _now_iso(),
                    int(result["duration_ms"]),
                    int(result["row_count"]),
                    result_hash,
                ),
            )
            con.commit()
            con.close()
        self._emit(
            "query.executed",
            {"org_id": org_id, "row_count": result["row_count"], "provider": provider},
        )
        result["result_hash"] = result_hash
        return result

    # ------------------------------------------------------------------ saved queries
    def save_query(self, org_id: str, name: str, dsl: str) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id is required")
        if not name or not name.strip():
            raise ValueError("name is required")
        compiled = self.compile_query(dsl)
        now = _now_iso()
        with self._lock:
            con = self._connect()
            cur = con.cursor()
            cur.execute(
                "SELECT id, created_at FROM saved_queries WHERE org_id = ? AND name = ?",
                (org_id, name),
            )
            existing = cur.fetchone()
            if existing:
                query_id = existing["id"]
                cur.execute(
                    """
                    UPDATE saved_queries
                       SET dsl_text = ?, compiled_plan_json = ?, updated_at = ?
                     WHERE id = ?
                    """,
                    (dsl, json.dumps(compiled.plan_json), now, query_id),
                )
                created_at = existing["created_at"]
            else:
                query_id = str(uuid.uuid4())
                cur.execute(
                    """
                    INSERT INTO saved_queries (
                        id, org_id, name, dsl_text, compiled_plan_json,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (query_id, org_id, name, dsl, json.dumps(compiled.plan_json), now, now),
                )
                created_at = now
            con.commit()
            con.close()
        self._emit("query.saved", {"org_id": org_id, "query_id": query_id, "name": name})
        return {
            "id": query_id,
            "org_id": org_id,
            "name": name,
            "dsl_text": dsl,
            "plan": compiled.plan_json,
            "created_at": created_at,
            "updated_at": now,
        }

    def list_queries(self, org_id: str) -> List[Dict[str, Any]]:
        if not org_id:
            raise ValueError("org_id is required")
        with self._lock:
            con = self._connect()
            cur = con.cursor()
            cur.execute(
                """
                SELECT id, org_id, name, dsl_text, compiled_plan_json,
                       created_at, updated_at
                  FROM saved_queries
                 WHERE org_id = ?
                 ORDER BY updated_at DESC
                """,
                (org_id,),
            )
            rows = cur.fetchall()
            con.close()
        out: List[Dict[str, Any]] = []
        for r in rows:
            try:
                plan = json.loads(r["compiled_plan_json"])
            except (TypeError, json.JSONDecodeError):
                plan = None
            out.append({
                "id": r["id"],
                "org_id": r["org_id"],
                "name": r["name"],
                "dsl_text": r["dsl_text"],
                "plan": plan,
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })
        return out

    def get_query(self, org_id: str, query_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            con = self._connect()
            cur = con.cursor()
            cur.execute(
                "SELECT * FROM saved_queries WHERE org_id = ? AND id = ?",
                (org_id, query_id),
            )
            r = cur.fetchone()
            con.close()
        if not r:
            return None
        try:
            plan = json.loads(r["compiled_plan_json"])
        except (TypeError, json.JSONDecodeError):
            plan = None
        return {
            "id": r["id"],
            "org_id": r["org_id"],
            "name": r["name"],
            "dsl_text": r["dsl_text"],
            "plan": plan,
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def delete_query(self, org_id: str, query_id: str) -> bool:
        with self._lock:
            con = self._connect()
            cur = con.cursor()
            cur.execute(
                "DELETE FROM saved_queries WHERE org_id = ? AND id = ?",
                (org_id, query_id),
            )
            deleted = cur.rowcount > 0
            con.commit()
            con.close()
        if deleted:
            self._emit("query.deleted", {"org_id": org_id, "query_id": query_id})
        return deleted

    # ------------------------------------------------------------------ history / schema / stats
    def list_history(self, org_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        if not org_id:
            raise ValueError("org_id is required")
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            con = self._connect()
            cur = con.cursor()
            cur.execute(
                """
                SELECT id, org_id, query_id, dsl_text, ran_at,
                       duration_ms, row_count, result_hash
                  FROM query_history
                 WHERE org_id = ?
                 ORDER BY ran_at DESC
                 LIMIT ?
                """,
                (org_id, limit),
            )
            rows = cur.fetchall()
            con.close()
        return [dict(r) for r in rows]

    def get_schema(self) -> Dict[str, Dict[str, str]]:
        return self.schema.to_dict()

    def stats(self, org_id: str) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id is required")
        with self._lock:
            con = self._connect()
            cur = con.cursor()
            cur.execute("SELECT COUNT(*) FROM saved_queries WHERE org_id = ?", (org_id,))
            saved = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM query_history WHERE org_id = ?", (org_id,))
            executed = cur.fetchone()[0]
            cur.execute(
                "SELECT COALESCE(AVG(duration_ms), 0) FROM query_history WHERE org_id = ?",
                (org_id,),
            )
            avg_duration = float(cur.fetchone()[0] or 0.0)
            cur.execute(
                "SELECT COALESCE(SUM(row_count), 0) FROM query_history WHERE org_id = ?",
                (org_id,),
            )
            total_rows = int(cur.fetchone()[0] or 0)
            con.close()
        return {
            "org_id": org_id,
            "saved_queries": int(saved),
            "executed_queries": int(executed),
            "avg_duration_ms": round(avg_duration, 2),
            "total_rows_returned": total_rows,
            "entity_count": len(self.schema.entities()),
        }

    # ------------------------------------------------------------------ event bus
    def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            # TrustGraph bus is typed sync-or-async depending on build — handle both
            result = bus.emit(f"security_query_language.{event}", payload)
            if hasattr(result, "__await__"):
                import asyncio
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(result)
                    else:
                        loop.run_until_complete(result)
                except RuntimeError:
                    # No loop — close the coroutine cleanly so we don't warn
                    result.close()
        except Exception:  # noqa: BLE001 - best-effort emit
            _logger.debug("trustgraph emit failed", exc_info=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Module-level singleton helper
# ---------------------------------------------------------------------------

_singleton: Optional[SecurityQueryLanguageEngine] = None
_singleton_lock = threading.Lock()


def get_engine() -> SecurityQueryLanguageEngine:
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = SecurityQueryLanguageEngine()
    return _singleton


__all__ = [
    "SQLSyntaxError",
    "SQLTypeError",
    "SQLPlanError",
    "Token",
    "TokenStream",
    "FilterNode",
    "LogicalNode",
    "QueryNode",
    "Parser",
    "SchemaRegistry",
    "QueryPlanner",
    "CompiledQuery",
    "InMemoryProvider",
    "SqliteProvider",
    "QueryExecutor",
    "SecurityQueryLanguageEngine",
    "get_engine",
]
