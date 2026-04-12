"""
Dashboard Builder — Custom dashboard layouts, widgets, sharing, and templates.

Provides a SQLite-backed engine for:
- Creating and managing personalised dashboards per user/org
- A library of configurable widget types (charts, KPI cards, tables, etc.)
- Template dashboards for common personas (CISO, SOC, Compliance, DevSecOps, Executive)
- Dashboard sharing (private → team → org → public) and cloning

Compliance: SOC2 CC6.1 (logical access), CC7.2 (monitoring)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_DEFAULT_DB = Path("data/dashboard_builder.db")


# ============================================================================
# ENUMS
# ============================================================================


class WidgetType(str, Enum):
    CHART_LINE = "chart_line"
    CHART_BAR = "chart_bar"
    CHART_PIE = "chart_pie"
    CHART_DONUT = "chart_donut"
    TABLE = "table"
    KPI_CARD = "kpi_card"
    TIMELINE = "timeline"
    HEATMAP = "heatmap"
    MAP = "map"
    MARKDOWN = "markdown"


class DashboardVisibility(str, Enum):
    PRIVATE = "private"
    TEAM = "team"
    ORG = "org"
    PUBLIC = "public"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class Widget(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: WidgetType
    title: str
    data_source: str = Field(description="Metric key or endpoint to query")
    config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Size, position, colors, filters, etc.",
    )
    order: int = 0


class Dashboard(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    owner_email: str
    visibility: DashboardVisibility = DashboardVisibility.PRIVATE
    widgets: List[Widget] = Field(default_factory=list)
    layout: Dict[str, Any] = Field(
        default_factory=lambda: {"cols": 12, "row_height": 60},
        description="Grid configuration",
    )
    org_id: str = "default"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    shared_with: List[str] = Field(default_factory=list, description="Email list")


class DashboardTemplate(BaseModel):
    id: str
    name: str
    description: str
    category: str
    widgets: List[Widget]
    layout: Dict[str, Any] = Field(default_factory=lambda: {"cols": 12, "row_height": 60})


# ============================================================================
# BUILT-IN TEMPLATES
# ============================================================================

_BUILTIN_TEMPLATES: List[DashboardTemplate] = [
    DashboardTemplate(
        id="tpl_ciso",
        name="CISO Executive Overview",
        description="High-level risk posture, compliance status, and critical findings for CISOs.",
        category="executive",
        widgets=[
            Widget(
                id="w_ciso_risk",
                type=WidgetType.KPI_CARD,
                title="Overall Risk Score",
                data_source="metrics/risk_score",
                config={"color": "#ef4444", "size": {"w": 3, "h": 2}},
                order=0,
            ),
            Widget(
                id="w_ciso_critical",
                type=WidgetType.KPI_CARD,
                title="Critical Findings",
                data_source="metrics/critical_findings_count",
                config={"color": "#f97316", "size": {"w": 3, "h": 2}},
                order=1,
            ),
            Widget(
                id="w_ciso_compliance",
                type=WidgetType.CHART_DONUT,
                title="Compliance Coverage",
                data_source="metrics/compliance_coverage",
                config={"size": {"w": 6, "h": 4}},
                order=2,
            ),
            Widget(
                id="w_ciso_trend",
                type=WidgetType.CHART_LINE,
                title="Risk Trend (90 days)",
                data_source="metrics/risk_trend",
                config={"size": {"w": 12, "h": 4}, "days": 90},
                order=3,
            ),
            Widget(
                id="w_ciso_mttr",
                type=WidgetType.KPI_CARD,
                title="Mean Time to Remediate",
                data_source="metrics/mttr",
                config={"unit": "hours", "size": {"w": 3, "h": 2}},
                order=4,
            ),
        ],
        layout={"cols": 12, "row_height": 60},
    ),
    DashboardTemplate(
        id="tpl_soc",
        name="SOC T1 Alert Triage",
        description="Real-time alert queue, severity heatmap, and LLM Council verdicts for SOC analysts.",
        category="operations",
        widgets=[
            Widget(
                id="w_soc_queue",
                type=WidgetType.TABLE,
                title="Active Alert Queue",
                data_source="findings/active",
                config={"size": {"w": 12, "h": 6}, "columns": ["severity", "title", "source", "created_at"]},
                order=0,
            ),
            Widget(
                id="w_soc_heatmap",
                type=WidgetType.HEATMAP,
                title="Alert Severity Heatmap",
                data_source="metrics/severity_heatmap",
                config={"size": {"w": 6, "h": 4}},
                order=1,
            ),
            Widget(
                id="w_soc_mttd",
                type=WidgetType.KPI_CARD,
                title="Mean Time to Detect",
                data_source="metrics/mttd",
                config={"unit": "minutes", "size": {"w": 3, "h": 2}},
                order=2,
            ),
            Widget(
                id="w_soc_fp",
                type=WidgetType.KPI_CARD,
                title="False Positive Rate",
                data_source="metrics/false_positive_rate",
                config={"unit": "%", "size": {"w": 3, "h": 2}},
                order=3,
            ),
            Widget(
                id="w_soc_timeline",
                type=WidgetType.TIMELINE,
                title="Incident Timeline",
                data_source="findings/timeline",
                config={"size": {"w": 12, "h": 4}, "hours": 24},
                order=4,
            ),
        ],
        layout={"cols": 12, "row_height": 60},
    ),
    DashboardTemplate(
        id="tpl_compliance",
        name="Compliance & Audit",
        description="Framework compliance status, evidence collection progress, and audit-ready reports.",
        category="compliance",
        widgets=[
            Widget(
                id="w_comp_frameworks",
                type=WidgetType.CHART_BAR,
                title="Framework Coverage",
                data_source="compliance/framework_coverage",
                config={"size": {"w": 8, "h": 4}, "frameworks": ["SOC2", "ISO27001", "PCI-DSS", "NIST-CSF"]},
                order=0,
            ),
            Widget(
                id="w_comp_score",
                type=WidgetType.KPI_CARD,
                title="Overall Compliance Score",
                data_source="compliance/overall_score",
                config={"unit": "%", "size": {"w": 4, "h": 2}},
                order=1,
            ),
            Widget(
                id="w_comp_controls",
                type=WidgetType.TABLE,
                title="Failed Controls",
                data_source="compliance/failed_controls",
                config={"size": {"w": 12, "h": 5}, "columns": ["control_id", "framework", "status", "owner"]},
                order=2,
            ),
            Widget(
                id="w_comp_evidence",
                type=WidgetType.CHART_PIE,
                title="Evidence Collection Status",
                data_source="compliance/evidence_status",
                config={"size": {"w": 4, "h": 4}},
                order=3,
            ),
        ],
        layout={"cols": 12, "row_height": 60},
    ),
    DashboardTemplate(
        id="tpl_devsecops",
        name="DevSecOps Pipeline",
        description="CI/CD security gate results, SAST/DAST findings, and SLA tracking for engineering teams.",
        category="engineering",
        widgets=[
            Widget(
                id="w_dso_gate",
                type=WidgetType.KPI_CARD,
                title="PR Gate Pass Rate",
                data_source="cicd/gate_pass_rate",
                config={"unit": "%", "size": {"w": 3, "h": 2}},
                order=0,
            ),
            Widget(
                id="w_dso_sast",
                type=WidgetType.CHART_BAR,
                title="SAST Findings by Severity",
                data_source="findings/by_severity?source=sast",
                config={"size": {"w": 6, "h": 4}},
                order=1,
            ),
            Widget(
                id="w_dso_dast",
                type=WidgetType.CHART_BAR,
                title="DAST Findings by Severity",
                data_source="findings/by_severity?source=dast",
                config={"size": {"w": 6, "h": 4}},
                order=2,
            ),
            Widget(
                id="w_dso_sla",
                type=WidgetType.KPI_CARD,
                title="SLA Compliance Rate",
                data_source="metrics/sla_compliance_rate",
                config={"unit": "%", "size": {"w": 3, "h": 2}},
                order=3,
            ),
            Widget(
                id="w_dso_table",
                type=WidgetType.TABLE,
                title="New Findings This Sprint",
                data_source="findings/recent?days=14",
                config={"size": {"w": 12, "h": 5}, "columns": ["title", "severity", "source", "repo", "status"]},
                order=4,
            ),
        ],
        layout={"cols": 12, "row_height": 60},
    ),
    DashboardTemplate(
        id="tpl_executive",
        name="Executive Summary",
        description="Board-ready metrics: risk trajectory, cost exposure, and threat landscape overview.",
        category="executive",
        widgets=[
            Widget(
                id="w_exec_risk_trend",
                type=WidgetType.CHART_LINE,
                title="Risk Trajectory (12 months)",
                data_source="metrics/risk_trend?months=12",
                config={"size": {"w": 8, "h": 4}},
                order=0,
            ),
            Widget(
                id="w_exec_posture",
                type=WidgetType.KPI_CARD,
                title="Security Posture Score",
                data_source="metrics/security_posture",
                config={"size": {"w": 4, "h": 2}},
                order=1,
            ),
            Widget(
                id="w_exec_threat_map",
                type=WidgetType.MAP,
                title="Threat Origin Map",
                data_source="threat_intel/geo_distribution",
                config={"size": {"w": 6, "h": 4}},
                order=2,
            ),
            Widget(
                id="w_exec_spend",
                type=WidgetType.CHART_BAR,
                title="Security Tool Cost vs Savings",
                data_source="metrics/cost_savings",
                config={"size": {"w": 6, "h": 4}},
                order=3,
            ),
            Widget(
                id="w_exec_summary",
                type=WidgetType.MARKDOWN,
                title="Executive Summary",
                data_source="reports/executive_summary",
                config={"size": {"w": 12, "h": 3}},
                order=4,
            ),
        ],
        layout={"cols": 12, "row_height": 60},
    ),
]

# ============================================================================
# WIDGET LIBRARY CATALOG
# ============================================================================

_WIDGET_LIBRARY: List[Dict[str, Any]] = [
    {
        "type": WidgetType.CHART_LINE,
        "label": "Line Chart",
        "description": "Time-series data over a continuous axis.",
        "config_schema": {
            "days": {"type": "integer", "default": 30},
            "size": {"type": "object", "default": {"w": 6, "h": 4}},
            "colors": {"type": "array", "default": []},
        },
    },
    {
        "type": WidgetType.CHART_BAR,
        "label": "Bar Chart",
        "description": "Comparative category data.",
        "config_schema": {
            "orientation": {"type": "string", "enum": ["vertical", "horizontal"], "default": "vertical"},
            "size": {"type": "object", "default": {"w": 6, "h": 4}},
            "colors": {"type": "array", "default": []},
        },
    },
    {
        "type": WidgetType.CHART_PIE,
        "label": "Pie Chart",
        "description": "Proportional distribution.",
        "config_schema": {
            "size": {"type": "object", "default": {"w": 4, "h": 4}},
            "show_legend": {"type": "boolean", "default": True},
        },
    },
    {
        "type": WidgetType.CHART_DONUT,
        "label": "Donut Chart",
        "description": "Proportional distribution with a centre metric.",
        "config_schema": {
            "size": {"type": "object", "default": {"w": 4, "h": 4}},
            "center_label": {"type": "string", "default": ""},
        },
    },
    {
        "type": WidgetType.TABLE,
        "label": "Data Table",
        "description": "Tabular data with sortable columns.",
        "config_schema": {
            "columns": {"type": "array", "default": []},
            "page_size": {"type": "integer", "default": 20},
            "size": {"type": "object", "default": {"w": 12, "h": 5}},
        },
    },
    {
        "type": WidgetType.KPI_CARD,
        "label": "KPI Card",
        "description": "Single metric highlight with optional trend indicator.",
        "config_schema": {
            "unit": {"type": "string", "default": ""},
            "show_trend": {"type": "boolean", "default": True},
            "color": {"type": "string", "default": "#3b82f6"},
            "size": {"type": "object", "default": {"w": 3, "h": 2}},
        },
    },
    {
        "type": WidgetType.TIMELINE,
        "label": "Event Timeline",
        "description": "Chronological event stream.",
        "config_schema": {
            "hours": {"type": "integer", "default": 24},
            "size": {"type": "object", "default": {"w": 12, "h": 4}},
        },
    },
    {
        "type": WidgetType.HEATMAP,
        "label": "Heatmap",
        "description": "Intensity matrix (e.g. severity over time).",
        "config_schema": {
            "size": {"type": "object", "default": {"w": 6, "h": 4}},
            "color_scale": {"type": "string", "default": "red"},
        },
    },
    {
        "type": WidgetType.MAP,
        "label": "Geo Map",
        "description": "Geographic data visualisation.",
        "config_schema": {
            "size": {"type": "object", "default": {"w": 6, "h": 4}},
            "zoom": {"type": "integer", "default": 2},
        },
    },
    {
        "type": WidgetType.MARKDOWN,
        "label": "Markdown Block",
        "description": "Free-form text / rendered markdown.",
        "config_schema": {
            "content": {"type": "string", "default": ""},
            "size": {"type": "object", "default": {"w": 12, "h": 3}},
        },
    },
]


# ============================================================================
# DASHBOARD BUILDER
# ============================================================================


class DashboardBuilder:
    """
    SQLite-backed dashboard management engine.

    All public methods are thread-safe via a module-level lock.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS dashboards (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    owner_email TEXT NOT NULL,
                    visibility  TEXT NOT NULL DEFAULT 'private',
                    widgets     TEXT NOT NULL DEFAULT '[]',
                    layout      TEXT NOT NULL DEFAULT '{}',
                    org_id      TEXT NOT NULL DEFAULT 'default',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL,
                    shared_with TEXT NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_dashboards_org ON dashboards(org_id);
                CREATE INDEX IF NOT EXISTS idx_dashboards_owner ON dashboards(owner_email);
                """
            )

    def _row_to_dashboard(self, row: sqlite3.Row) -> Dashboard:
        return Dashboard(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            owner_email=row["owner_email"],
            visibility=DashboardVisibility(row["visibility"]),
            widgets=[Widget(**w) for w in json.loads(row["widgets"])],
            layout=json.loads(row["layout"]),
            org_id=row["org_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            shared_with=json.loads(row["shared_with"]),
        )

    def _save_dashboard(self, conn: sqlite3.Connection, dash: Dashboard) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO dashboards
                (id, name, description, owner_email, visibility, widgets,
                 layout, org_id, created_at, updated_at, shared_with)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                dash.id,
                dash.name,
                dash.description,
                dash.owner_email,
                dash.visibility.value,
                json.dumps([w.model_dump() for w in dash.widgets]),
                json.dumps(dash.layout),
                dash.org_id,
                dash.created_at.isoformat(),
                dash.updated_at.isoformat(),
                json.dumps(dash.shared_with),
            ),
        )

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Dashboard CRUD
    # ------------------------------------------------------------------

    def create_dashboard(
        self,
        name: str,
        description: str = "",
        owner: str = "unknown",
        org_id: str = "default",
    ) -> Dashboard:
        now = self._now()
        dash = Dashboard(
            name=name,
            description=description,
            owner_email=owner,
            org_id=org_id,
            created_at=now,
            updated_at=now,
        )
        with self._lock, self._connect() as conn:
            self._save_dashboard(conn, dash)
        _logger.info("Created dashboard %s for %s", dash.id, owner)
        return dash

    def get_dashboard(self, dashboard_id: str) -> Dashboard:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM dashboards WHERE id = ?", (dashboard_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"Dashboard not found: {dashboard_id}")
        return self._row_to_dashboard(row)

    def list_dashboards(
        self,
        org_id: Optional[str] = None,
        owner: Optional[str] = None,
    ) -> List[Dashboard]:
        query = "SELECT * FROM dashboards WHERE 1=1"
        params: List[Any] = []
        if org_id is not None:
            query += " AND org_id = ?"
            params.append(org_id)
        if owner is not None:
            query += " AND owner_email = ?"
            params.append(owner)
        query += " ORDER BY updated_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dashboard(r) for r in rows]

    def update_dashboard(self, dashboard_id: str, updates: Dict[str, Any]) -> Dashboard:
        with self._lock:
            dash = self.get_dashboard(dashboard_id)
            for key, value in updates.items():
                if key in {"id", "created_at", "widgets"}:
                    continue  # protected fields
                if key == "visibility":
                    value = DashboardVisibility(value)
                setattr(dash, key, value)
            dash.updated_at = self._now()
            with self._connect() as conn:
                self._save_dashboard(conn, dash)
        return dash

    def delete_dashboard(self, dashboard_id: str) -> None:
        with self._lock, self._connect() as conn:
            result = conn.execute(
                "DELETE FROM dashboards WHERE id = ?", (dashboard_id,)
            )
            if result.rowcount == 0:
                raise KeyError(f"Dashboard not found: {dashboard_id}")
        _logger.info("Deleted dashboard %s", dashboard_id)

    # ------------------------------------------------------------------
    # Widget management
    # ------------------------------------------------------------------

    def add_widget(self, dashboard_id: str, widget: Widget) -> Widget:
        with self._lock:
            dash = self.get_dashboard(dashboard_id)
            # Assign next order if not provided
            if widget.order == 0 and dash.widgets:
                widget = widget.model_copy(
                    update={"order": max(w.order for w in dash.widgets) + 1}
                )
            dash.widgets.append(widget)
            dash.updated_at = self._now()
            with self._connect() as conn:
                self._save_dashboard(conn, dash)
        return widget

    def update_widget(
        self, dashboard_id: str, widget_id: str, updates: Dict[str, Any]
    ) -> Widget:
        with self._lock:
            dash = self.get_dashboard(dashboard_id)
            idx = next(
                (i for i, w in enumerate(dash.widgets) if w.id == widget_id), None
            )
            if idx is None:
                raise KeyError(f"Widget not found: {widget_id}")
            existing = dash.widgets[idx]
            updated = existing.model_copy(update={k: v for k, v in updates.items() if k != "id"})
            if "type" in updates:
                updated = updated.model_copy(update={"type": WidgetType(updates["type"])})
            dash.widgets[idx] = updated
            dash.updated_at = self._now()
            with self._connect() as conn:
                self._save_dashboard(conn, dash)
        return updated

    def remove_widget(self, dashboard_id: str, widget_id: str) -> None:
        with self._lock:
            dash = self.get_dashboard(dashboard_id)
            before = len(dash.widgets)
            dash.widgets = [w for w in dash.widgets if w.id != widget_id]
            if len(dash.widgets) == before:
                raise KeyError(f"Widget not found: {widget_id}")
            dash.updated_at = self._now()
            with self._connect() as conn:
                self._save_dashboard(conn, dash)

    def reorder_widgets(self, dashboard_id: str, widget_ids: List[str]) -> None:
        """Assign new ordinal positions matching the supplied id order."""
        with self._lock:
            dash = self.get_dashboard(dashboard_id)
            id_to_widget = {w.id: w for w in dash.widgets}
            reordered: List[Widget] = []
            for pos, wid in enumerate(widget_ids):
                if wid not in id_to_widget:
                    raise KeyError(f"Widget not found: {wid}")
                reordered.append(id_to_widget[wid].model_copy(update={"order": pos}))
            # Append any widgets not mentioned, preserving their relative order
            mentioned = set(widget_ids)
            for w in dash.widgets:
                if w.id not in mentioned:
                    reordered.append(w.model_copy(update={"order": len(reordered)}))
            dash.widgets = reordered
            dash.updated_at = self._now()
            with self._connect() as conn:
                self._save_dashboard(conn, dash)

    # ------------------------------------------------------------------
    # Sharing & cloning
    # ------------------------------------------------------------------

    def share_dashboard(
        self,
        dashboard_id: str,
        emails: List[str],
        visibility: Optional[DashboardVisibility] = None,
    ) -> Dashboard:
        with self._lock:
            dash = self.get_dashboard(dashboard_id)
            existing = set(dash.shared_with)
            existing.update(emails)
            dash.shared_with = sorted(existing)
            if visibility is not None:
                dash.visibility = visibility
            dash.updated_at = self._now()
            with self._connect() as conn:
                self._save_dashboard(conn, dash)
        return dash

    def clone_dashboard(
        self,
        dashboard_id: str,
        new_name: str,
        new_owner: str,
    ) -> Dashboard:
        source = self.get_dashboard(dashboard_id)
        now = self._now()
        cloned = Dashboard(
            name=new_name,
            description=f"Clone of: {source.description}",
            owner_email=new_owner,
            visibility=DashboardVisibility.PRIVATE,
            widgets=[
                w.model_copy(update={"id": str(uuid.uuid4())}) for w in source.widgets
            ],
            layout=dict(source.layout),
            org_id=source.org_id,
            created_at=now,
            updated_at=now,
        )
        with self._lock, self._connect() as conn:
            self._save_dashboard(conn, cloned)
        _logger.info("Cloned dashboard %s -> %s", dashboard_id, cloned.id)
        return cloned

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------

    def get_templates(self) -> List[DashboardTemplate]:
        return list(_BUILTIN_TEMPLATES)

    def create_from_template(
        self,
        template_id: str,
        name: str,
        owner: str,
        org_id: str = "default",
    ) -> Dashboard:
        tpl = next((t for t in _BUILTIN_TEMPLATES if t.id == template_id), None)
        if tpl is None:
            raise KeyError(f"Template not found: {template_id}")
        now = self._now()
        dash = Dashboard(
            name=name,
            description=tpl.description,
            owner_email=owner,
            visibility=DashboardVisibility.PRIVATE,
            widgets=[
                w.model_copy(update={"id": str(uuid.uuid4())}) for w in tpl.widgets
            ],
            layout=dict(tpl.layout),
            org_id=org_id,
            created_at=now,
            updated_at=now,
        )
        with self._lock, self._connect() as conn:
            self._save_dashboard(conn, dash)
        return dash

    # ------------------------------------------------------------------
    # Widget library & stats
    # ------------------------------------------------------------------

    def get_widget_library(self) -> List[Dict[str, Any]]:
        return [dict(entry) for entry in _WIDGET_LIBRARY]

    def get_dashboard_stats(self, org_id: str = "default") -> Dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM dashboards WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            by_visibility = {
                row["visibility"]: row["cnt"]
                for row in conn.execute(
                    "SELECT visibility, COUNT(*) AS cnt FROM dashboards WHERE org_id = ? GROUP BY visibility",
                    (org_id,),
                ).fetchall()
            }
            shared_count = conn.execute(
                "SELECT COUNT(*) FROM dashboards WHERE org_id = ? AND shared_with != '[]'",
                (org_id,),
            ).fetchone()[0]
        return {
            "org_id": org_id,
            "total_dashboards": total,
            "by_visibility": by_visibility,
            "shared_dashboards": shared_count,
            "template_count": len(_BUILTIN_TEMPLATES),
            "widget_types_available": len(_WIDGET_LIBRARY),
        }
