"""Attack Surface Continuous Monitoring — Snapshots, Diffs, Scoring, Attack Paths.

Tracks changes in attack surface over time by capturing periodic snapshots
and diffing them to surface new exposures, removed services, and risk changes.

Usage:
    from core.attack_surface_monitor import get_attack_surface_monitor
    monitor = get_attack_surface_monitor()
    snapshot = monitor.take_snapshot("localhost")
    score = monitor.calculate_attack_surface_score(snapshot)
"""

from __future__ import annotations

import os
import socket
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_ASM_MONITOR_DB", ".fixops_data/attack_surface_monitor.db")

# ---------------------------------------------------------------------------
# Known-risky port catalogue
# ---------------------------------------------------------------------------

_RISKY_PORT_MAP: Dict[int, Tuple[str, str]] = {
    21: ("FTP", "high"),
    22: ("SSH", "medium"),
    23: ("Telnet", "critical"),
    25: ("SMTP", "medium"),
    53: ("DNS", "low"),
    80: ("HTTP", "low"),
    110: ("POP3", "medium"),
    135: ("MSRPC", "high"),
    139: ("NetBIOS", "high"),
    143: ("IMAP", "low"),
    443: ("HTTPS", "low"),
    445: ("SMB", "high"),
    993: ("IMAPS", "low"),
    995: ("POP3S", "low"),
    1433: ("MSSQL", "high"),
    1521: ("Oracle", "high"),
    2049: ("NFS", "high"),
    3000: ("Dev HTTP", "medium"),
    3306: ("MySQL", "high"),
    3389: ("RDP", "critical"),
    4443: ("HTTPS-alt", "low"),
    5000: ("Dev HTTP", "medium"),
    5432: ("PostgreSQL", "high"),
    5900: ("VNC", "critical"),
    6379: ("Redis", "critical"),
    6443: ("Kubernetes API", "high"),
    8000: ("Dev HTTP", "medium"),
    8008: ("HTTP-alt", "low"),
    8080: ("HTTP-proxy", "medium"),
    8443: ("HTTPS-alt", "low"),
    8888: ("Jupyter", "critical"),
    9000: ("PHP-FPM/SonarQube", "high"),
    9090: ("Prometheus", "high"),
    9200: ("Elasticsearch", "critical"),
    9300: ("Elasticsearch cluster", "high"),
    11211: ("Memcached", "high"),
    27017: ("MongoDB", "critical"),
    50000: ("IBM DB2", "high"),
}

_ADMIN_PORTS = {8888, 9090, 6443, 9200, 9300, 6379, 27017, 11211, 5900, 3389, 23}

_SECRET_PATTERNS = [
    "password", "secret", "api_key", "apikey", "token", "private_key",
    "aws_access", "aws_secret", "database_url", "db_password",
]

# Common well-known ports to scan on localhost
_LOCAL_SCAN_PORTS = list(_RISKY_PORT_MAP.keys()) + [
    4000, 4200, 5173, 7000, 8001, 8002, 8003, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 9001, 9002, 9003, 15672, 16686,
]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ServiceInfo(BaseModel):
    port: int
    service: str
    risk_level: str = "info"
    banner: str = ""


class AttackSurfaceSnapshot(BaseModel):
    id: str = Field(default_factory=lambda: f"snap-{uuid.uuid4().hex[:12]}")
    target: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    open_ports: List[int] = Field(default_factory=list)
    services: List[ServiceInfo] = Field(default_factory=list)
    endpoints: List[str] = Field(default_factory=list)
    deps: List[str] = Field(default_factory=list)
    secrets_exposed: List[str] = Field(default_factory=list)
    score: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackSurfaceDiff(BaseModel):
    id: str = Field(default_factory=lambda: f"diff-{uuid.uuid4().hex[:12]}")
    snapshot_old_id: str
    snapshot_new_id: str
    target: str
    computed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    added_ports: List[int] = Field(default_factory=list)
    removed_ports: List[int] = Field(default_factory=list)
    added_services: List[ServiceInfo] = Field(default_factory=list)
    removed_services: List[ServiceInfo] = Field(default_factory=list)
    added_endpoints: List[str] = Field(default_factory=list)
    removed_endpoints: List[str] = Field(default_factory=list)
    new_secrets: List[str] = Field(default_factory=list)
    closed_secrets: List[str] = Field(default_factory=list)
    score_delta: float = 0.0
    risk_increased: bool = False
    change_count: int = 0


class AttackPath(BaseModel):
    id: str = Field(default_factory=lambda: f"apath-{uuid.uuid4().hex[:10]}")
    name: str
    entry_point: str
    target: str
    steps: List[str] = Field(default_factory=list)
    risk_score: float = 0.0
    techniques: List[str] = Field(default_factory=list)
    description: str = ""


class MonitorSession(BaseModel):
    id: str = Field(default_factory=lambda: f"mon-{uuid.uuid4().hex[:10]}")
    target: str
    interval_seconds: int = 300
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_snapshot_id: Optional[str] = None
    snapshot_count: int = 0
    active: bool = True


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------


class AttackSurfaceMonitor:
    """Continuously monitors and diffs attack surface changes."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._monitors: Dict[str, MonitorSession] = {}
        self._monitor_threads: Dict[str, threading.Thread] = {}
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._init_db()
        logger.info("AttackSurfaceMonitor initialised", db=db_path)

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS diffs (
                    id TEXT PRIMARY KEY,
                    snapshot_old_id TEXT NOT NULL,
                    snapshot_new_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    computed_at TEXT NOT NULL,
                    data TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_snapshots_target ON snapshots(target);
                CREATE INDEX IF NOT EXISTS idx_diffs_target ON diffs(target);
            """)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def take_snapshot(
        self,
        target: str,
        port_timeout: float = 0.1,
        endpoints: Optional[List[str]] = None,
        deps: Optional[List[str]] = None,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> AttackSurfaceSnapshot:
        """Capture current attack surface state for a target.

        Discovers: open ports (socket scan), exposed endpoints,
        dependency list, exposed secrets in env vars.
        """
        logger.info("Taking attack surface snapshot", target=target)

        open_ports = self._scan_ports(target, port_timeout)
        services = self._classify_services(open_ports)
        discovered_endpoints = endpoints or self._infer_endpoints(target, open_ports)
        discovered_deps = deps or []
        secrets_exposed = self._scan_secrets(env_vars or {})

        snap = AttackSurfaceSnapshot(
            target=target,
            open_ports=open_ports,
            services=services,
            endpoints=discovered_endpoints,
            deps=discovered_deps,
            secrets_exposed=secrets_exposed,
        )
        snap.score = self.calculate_attack_surface_score(snap)

        self._save_snapshot(snap)
        return snap

    def _scan_ports(self, host: str, timeout: float = 0.1) -> List[int]:
        """Socket-based port scan. Returns list of open port numbers."""
        open_ports: List[int] = []
        for port in _LOCAL_SCAN_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(port)
            except OSError:
                pass
        return sorted(set(open_ports))

    def _classify_services(self, ports: List[int]) -> List[ServiceInfo]:
        services: List[ServiceInfo] = []
        for port in ports:
            if port in _RISKY_PORT_MAP:
                name, risk = _RISKY_PORT_MAP[port]
            else:
                name = f"unknown-{port}"
                risk = "info"
            services.append(ServiceInfo(port=port, service=name, risk_level=risk))
        return services

    def _infer_endpoints(self, host: str, open_ports: List[int]) -> List[str]:
        endpoints: List[str] = []
        http_ports = {p for p in open_ports if p in {80, 8000, 8008, 8080, 8081, 8082, 8083, 8090}}
        https_ports = {p for p in open_ports if p in {443, 4443, 8443, 9443}}
        for p in sorted(http_ports):
            endpoints.append(f"http://{host}:{p}/")
        for p in sorted(https_ports):
            endpoints.append(f"https://{host}:{p}/")
        return endpoints

    def _scan_secrets(self, env_vars: Dict[str, str]) -> List[str]:
        """Check env vars for exposed secret patterns."""
        exposed: List[str] = []
        for key, value in env_vars.items():
            lower_key = key.lower()
            if any(pat in lower_key for pat in _SECRET_PATTERNS) and value:
                exposed.append(key)
        return exposed

    def _save_snapshot(self, snap: AttackSurfaceSnapshot) -> None:
        with self._lock, self._get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO snapshots (id, target, timestamp, data) VALUES (?,?,?,?)",
                (snap.id, snap.target, snap.timestamp, snap.model_dump_json()),
            )

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    def diff_snapshots(
        self,
        old: AttackSurfaceSnapshot,
        new: AttackSurfaceSnapshot,
    ) -> AttackSurfaceDiff:
        """Compare two snapshots and identify changes."""
        old_ports = set(old.open_ports)
        new_ports = set(new.open_ports)
        added_ports = sorted(new_ports - old_ports)
        removed_ports = sorted(old_ports - new_ports)

        old_svc_map = {s.port: s for s in old.services}
        new_svc_map = {s.port: s for s in new.services}
        added_services = [new_svc_map[p] for p in added_ports if p in new_svc_map]
        removed_services = [old_svc_map[p] for p in removed_ports if p in old_svc_map]

        old_ep = set(old.endpoints)
        new_ep = set(new.endpoints)
        added_endpoints = sorted(new_ep - old_ep)
        removed_endpoints = sorted(old_ep - new_ep)

        old_sec = set(old.secrets_exposed)
        new_sec = set(new.secrets_exposed)
        new_secrets = sorted(new_sec - old_sec)
        closed_secrets = sorted(old_sec - new_sec)

        score_delta = new.score - old.score

        change_count = (
            len(added_ports)
            + len(removed_ports)
            + len(added_endpoints)
            + len(removed_endpoints)
            + len(new_secrets)
        )

        diff = AttackSurfaceDiff(
            snapshot_old_id=old.id,
            snapshot_new_id=new.id,
            target=new.target,
            added_ports=added_ports,
            removed_ports=removed_ports,
            added_services=added_services,
            removed_services=removed_services,
            added_endpoints=added_endpoints,
            removed_endpoints=removed_endpoints,
            new_secrets=new_secrets,
            closed_secrets=closed_secrets,
            score_delta=score_delta,
            risk_increased=score_delta > 0,
            change_count=change_count,
        )

        self._save_diff(diff)
        return diff

    def _save_diff(self, diff: AttackSurfaceDiff) -> None:
        with self._lock, self._get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO diffs (id, snapshot_old_id, snapshot_new_id, target, computed_at, data) "
                "VALUES (?,?,?,?,?,?)",
                (diff.id, diff.snapshot_old_id, diff.snapshot_new_id,
                 diff.target, diff.computed_at, diff.model_dump_json()),
            )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def calculate_attack_surface_score(self, snapshot: AttackSurfaceSnapshot) -> float:
        """Score the attack surface 0-100 (lower = better).

        Factors: exposed ports, admin interfaces, known-risky services,
                 public endpoints, hardcoded secrets.
        """
        score = 0.0

        # Port exposure (up to 40 points)
        port_score = 0.0
        for port in snapshot.open_ports:
            if port in _RISKY_PORT_MAP:
                _, risk = _RISKY_PORT_MAP[port]
                port_score += {"critical": 8.0, "high": 4.0, "medium": 2.0, "low": 0.5}.get(risk, 0.5)
            else:
                port_score += 1.0
        score += min(port_score, 40.0)

        # Admin interfaces exposed (up to 20 points)
        admin_exposed = sum(1 for p in snapshot.open_ports if p in _ADMIN_PORTS)
        score += min(admin_exposed * 5.0, 20.0)

        # Public endpoints (up to 20 points)
        score += min(len(snapshot.endpoints) * 2.0, 20.0)

        # Secrets exposed (up to 15 points)
        score += min(len(snapshot.secrets_exposed) * 5.0, 15.0)

        # Dependency count as proxy for attack surface breadth (up to 5 points)
        score += min(len(snapshot.deps) * 0.1, 5.0)

        return round(min(score, 100.0), 2)

    # ------------------------------------------------------------------
    # Shadow IT detection
    # ------------------------------------------------------------------

    def detect_shadow_it(
        self,
        network_range: str = "127.0.0.1",
        port_timeout: float = 0.1,
    ) -> List[Dict[str, Any]]:
        """Detect unknown/unauthorized services on the local network.

        Scans 127.0.0.1 common ports and flags unexpected open ports.
        """
        findings: List[Dict[str, Any]] = []
        open_ports = self._scan_ports(network_range, port_timeout)

        for port in open_ports:
            if port in _RISKY_PORT_MAP:
                service_name, risk = _RISKY_PORT_MAP[port]
            else:
                service_name = f"unknown-{port}"
                risk = "medium"

            # All non-standard open ports are shadow IT candidates
            finding = {
                "host": network_range,
                "port": port,
                "service": service_name,
                "risk_level": risk,
                "reason": "Unexpected open port detected on local network",
                "is_admin_interface": port in _ADMIN_PORTS,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
            findings.append(finding)
            logger.info("Shadow IT detected", port=port, service=service_name, risk=risk)

        return findings

    # ------------------------------------------------------------------
    # Attack path generation
    # ------------------------------------------------------------------

    def generate_attack_paths(self, findings: List[Dict[str, Any]]) -> List[AttackPath]:
        """Generate likely attack paths from current surface.

        Simple graph: entry point → lateral movement → target.
        Produces one path per high/critical finding, chaining through
        any intermediate medium-risk services.
        """
        paths: List[AttackPath] = []

        critical_ports = [f for f in findings if f.get("risk_level") in ("critical", "high")]
        medium_ports = [f for f in findings if f.get("risk_level") == "medium"]

        for entry in critical_ports:
            entry_label = f"{entry.get('host','?')}:{entry.get('port')} ({entry.get('service','')})"

            # Simple pivot: web → admin
            steps: List[str] = [entry_label]
            techniques: List[str] = []

            port = entry.get("port", 0)
            if port in (80, 8080, 443, 8443):
                techniques += ["T1190 (Exploit Public-Facing Application)"]
                steps.append("Exploit web endpoint")
            elif port in (22,):
                techniques += ["T1021.004 (SSH)"]
                steps.append("Brute-force / credential stuffing SSH")
            elif port in (3389,):
                techniques += ["T1021.001 (RDP)"]
                steps.append("Exploit RDP")
            elif port in (6379, 27017, 9200):
                techniques += ["T1213 (Data from Information Repositories)"]
                steps.append("Direct unauthenticated DB access")
            elif port in (5900,):
                techniques += ["T1021.005 (VNC)"]
                steps.append("VNC lateral movement")
            else:
                techniques += ["T1078 (Valid Accounts)"]
                steps.append("Exploit exposed service")

            # Pivot through medium-risk services
            for pivot in medium_ports[:2]:
                pivot_label = f"{pivot.get('host','?')}:{pivot.get('port')} ({pivot.get('service','')})"
                steps.append(f"Lateral movement via {pivot_label}")
                techniques.append("T1570 (Lateral Tool Transfer)")

            steps.append("Access internal target")

            risk = {"critical": 90.0, "high": 70.0}.get(str(entry.get("risk_level")), 50.0)
            risk += len(medium_ports) * 2.0

            path = AttackPath(
                name=f"Path via {entry.get('service', 'unknown')} port {port}",
                entry_point=entry_label,
                target="internal-target",
                steps=steps,
                risk_score=round(min(risk, 100.0), 2),
                techniques=list(dict.fromkeys(techniques)),
                description=(
                    f"Attacker exploits {entry.get('service','')} on port {port} "
                    f"then pivots through {len(medium_ports)} intermediate services."
                ),
            )
            paths.append(path)

        return paths

    # ------------------------------------------------------------------
    # Continuous monitoring
    # ------------------------------------------------------------------

    def start_monitoring(
        self,
        target: str,
        interval_seconds: int = 300,
        port_timeout: float = 0.1,
    ) -> MonitorSession:
        """Start continuous monitoring for a target (background thread)."""
        session = MonitorSession(target=target, interval_seconds=interval_seconds)
        self._monitors[session.id] = session

        def _loop() -> None:
            import time
            prev_snap: Optional[AttackSurfaceSnapshot] = None
            while self._monitors.get(session.id, MonitorSession(target="", active=False)).active:
                snap = self.take_snapshot(target, port_timeout=port_timeout)
                session.last_snapshot_id = snap.id
                session.snapshot_count += 1
                if prev_snap is not None:
                    diff = self.diff_snapshots(prev_snap, snap)
                    if diff.risk_increased:
                        logger.warning(
                            "Attack surface risk increased",
                            target=target,
                            score_delta=diff.score_delta,
                            new_ports=diff.added_ports,
                        )
                prev_snap = snap
                time.sleep(interval_seconds)

        t = threading.Thread(target=_loop, name=f"asm-monitor-{session.id}", daemon=True)
        t.start()
        self._monitor_threads[session.id] = t
        logger.info("Monitoring started", target=target, session_id=session.id, interval=interval_seconds)
        return session

    def stop_monitoring(self, session_id: str) -> bool:
        """Stop a monitoring session."""
        session = self._monitors.get(session_id)
        if not session:
            return False
        session.active = False
        logger.info("Monitoring stopped", session_id=session_id)
        return True

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_snapshot(self, snapshot_id: str) -> Optional[AttackSurfaceSnapshot]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT data FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if not row:
            return None
        return AttackSurfaceSnapshot.model_validate_json(row["data"])

    def list_snapshots(self, target: str, limit: int = 50) -> List[AttackSurfaceSnapshot]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT data FROM snapshots WHERE target=? ORDER BY timestamp DESC LIMIT ?",
                (target, limit),
            ).fetchall()
        return [AttackSurfaceSnapshot.model_validate_json(r["data"]) for r in rows]

    def get_diff(self, diff_id: str) -> Optional[AttackSurfaceDiff]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT data FROM diffs WHERE id=?", (diff_id,)).fetchone()
        if not row:
            return None
        return AttackSurfaceDiff.model_validate_json(row["data"])

    def get_current_score(self, target: str, port_timeout: float = 0.1) -> Dict[str, Any]:
        """Take a fresh snapshot and return its score."""
        snap = self.take_snapshot(target, port_timeout=port_timeout)
        return {
            "target": target,
            "score": snap.score,
            "snapshot_id": snap.id,
            "open_ports": snap.open_ports,
            "services": [s.model_dump() for s in snap.services],
            "endpoints": snap.endpoints,
            "secrets_exposed_count": len(snap.secrets_exposed),
            "timestamp": snap.timestamp,
        }


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------

_monitor_instance: Optional[AttackSurfaceMonitor] = None
_monitor_lock = threading.Lock()


def get_attack_surface_monitor() -> AttackSurfaceMonitor:
    global _monitor_instance
    with _monitor_lock:
        if _monitor_instance is None:
            _monitor_instance = AttackSurfaceMonitor()
    return _monitor_instance
