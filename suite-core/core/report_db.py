"""
Report database manager using SQLite.
"""
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.report_models import (
    Report,
    ReportFormat,
    ReportSchedule,
    ReportStatus,
    ReportTemplate,
    ReportType,
)


class ReportDB:
    """Database manager for report records."""

    def __init__(self, db_path: str = "data/reports.db"):
        """Initialize database connection."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Initialize database tables."""
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    format TEXT NOT NULL,
                    status TEXT NOT NULL,
                    parameters TEXT,
                    file_path TEXT,
                    file_size INTEGER,
                    generated_by TEXT,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS report_schedules (
                    id TEXT PRIMARY KEY,
                    report_type TEXT NOT NULL,
                    format TEXT NOT NULL,
                    schedule_cron TEXT NOT NULL,
                    parameters TEXT,
                    enabled INTEGER NOT NULL,
                    last_run_at TEXT,
                    next_run_at TEXT,
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS report_templates (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    report_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    template_config TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
                CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
                CREATE INDEX IF NOT EXISTS idx_report_schedules_enabled ON report_schedules(enabled);
            """
            )
            conn.commit()
        finally:
            conn.close()

    def create_report(self, report: Report) -> Report:
        """Create new report."""
        if not report.id:
            report.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    report.id,
                    report.name,
                    report.report_type.value,
                    report.format.value,
                    report.status.value,
                    json.dumps(report.parameters),
                    report.file_path,
                    report.file_size,
                    report.generated_by,
                    report.error_message,
                    report.created_at.isoformat(),
                    report.completed_at.isoformat() if report.completed_at else None,
                ),
            )
            conn.commit()
            return report
        finally:
            conn.close()

    def get_report(self, report_id: str) -> Optional[Report]:
        """Get report by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM reports WHERE id = ?", (report_id,)
            ).fetchone()
            if row:
                return self._row_to_report(row)
            return None
        finally:
            conn.close()

    def list_reports(
        self, report_type: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[Report]:
        """List reports with optional filtering."""
        conn = self._get_connection()
        try:
            if report_type:
                rows = conn.execute(
                    "SELECT * FROM reports WHERE report_type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (report_type, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_report(row) for row in rows]
        finally:
            conn.close()

    def update_report(self, report: Report) -> Report:
        """Update report."""
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE reports SET status=?, file_path=?, file_size=?, error_message=?, completed_at=? WHERE id=?""",
                (
                    report.status.value,
                    report.file_path,
                    report.file_size,
                    report.error_message,
                    report.completed_at.isoformat() if report.completed_at else None,
                    report.id,
                ),
            )
            conn.commit()
            return report
        finally:
            conn.close()

    def delete_report(self, report_id: str) -> bool:
        """Delete report."""
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def create_schedule(self, schedule: ReportSchedule) -> ReportSchedule:
        """Create report schedule."""
        if not schedule.id:
            schedule.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO report_schedules VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    schedule.id,
                    schedule.report_type.value,
                    schedule.format.value,
                    schedule.schedule_cron,
                    json.dumps(schedule.parameters),
                    1 if schedule.enabled else 0,
                    schedule.last_run_at.isoformat() if schedule.last_run_at else None,
                    schedule.next_run_at.isoformat() if schedule.next_run_at else None,
                    schedule.created_by,
                    schedule.created_at.isoformat(),
                    schedule.updated_at.isoformat(),
                ),
            )
            conn.commit()
            return schedule
        finally:
            conn.close()

    def list_schedules(self, limit: int = 100, offset: int = 0) -> List[ReportSchedule]:
        """List report schedules."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM report_schedules ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [self._row_to_schedule(row) for row in rows]
        finally:
            conn.close()

    def create_template(self, template: ReportTemplate) -> ReportTemplate:
        """Create report template."""
        if not template.id:
            template.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO report_templates VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    template.id,
                    template.name,
                    template.report_type.value,
                    template.description,
                    json.dumps(template.template_config),
                    template.created_at.isoformat(),
                    template.updated_at.isoformat(),
                ),
            )
            conn.commit()
            return template
        finally:
            conn.close()

    def list_templates(self, limit: int = 100, offset: int = 0) -> List[ReportTemplate]:
        """List report templates."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM report_templates ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [self._row_to_template(row) for row in rows]
        finally:
            conn.close()

    def _row_to_report(self, row) -> Report:
        """Convert database row to Report object."""
        return Report(
            id=row["id"],
            name=row["name"],
            report_type=ReportType(row["report_type"]),
            format=ReportFormat(row["format"]),
            status=ReportStatus(row["status"]),
            parameters=json.loads(row["parameters"]) if row["parameters"] else {},
            file_path=row["file_path"],
            file_size=row["file_size"],
            generated_by=row["generated_by"],
            error_message=row["error_message"],
            created_at=datetime.fromisoformat(row["created_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"])
                if row["completed_at"]
                else None
            ),
        )

    def _row_to_schedule(self, row) -> ReportSchedule:
        """Convert database row to ReportSchedule object."""
        return ReportSchedule(
            id=row["id"],
            report_type=ReportType(row["report_type"]),
            format=ReportFormat(row["format"]),
            schedule_cron=row["schedule_cron"],
            parameters=json.loads(row["parameters"]) if row["parameters"] else {},
            enabled=bool(row["enabled"]),
            last_run_at=(
                datetime.fromisoformat(row["last_run_at"])
                if row["last_run_at"]
                else None
            ),
            next_run_at=(
                datetime.fromisoformat(row["next_run_at"])
                if row["next_run_at"]
                else None
            ),
            created_by=row["created_by"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def _row_to_template(self, row) -> ReportTemplate:
        """Convert database row to ReportTemplate object."""
        return ReportTemplate(
            id=row["id"],
            name=row["name"],
            report_type=ReportType(row["report_type"]),
            description=row["description"],
            template_config=json.loads(row["template_config"])
            if row["template_config"]
            else {},
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
