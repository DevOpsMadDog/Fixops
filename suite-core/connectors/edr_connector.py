"""ALDECI EDR/XDR Connector — replaces CrowdStrike/SentinelOne/Defender XDR with OSS.

Connects to:
  - Falco (Kubernetes/Linux runtime detection — replaces CrowdStrike Falcon)
  - osquery (host-level telemetry — replaces CrowdStrike Falcon Insight)
  - Wazuh agent (HIDS — replaces SentinelOne / Defender XDR)
  - Suricata (network IDS — augments Defender XDR federation)

Sources:
  1. Live tail of Falco JSON logs from a kind/k8s cluster
     (kubectl logs -n falco daemonset/falco --tail=N)
  2. osquery scheduled query results (JSON)
  3. Wazuh alerts.json (HIDS rule matches)
  4. Embedded fallback: official Falco rule-pack sample events (REAL format,
     synthetic content) for demos when no live cluster is reachable.

Pipeline:
  raw_event → normalize → EDREngine.ingest_process_event
                       → SecurityFindingsEngine.record_finding
                                              (source_tool="edr_via_falco" /
                                               "edr_via_osquery" /
                                               "edr_via_wazuh")

Multi-tenant: every event is attributed to an explicit ``org_id`` so tenant
isolation in the persistence layer is preserved.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Falco priority → ALDECI severity mapping
# ---------------------------------------------------------------------------
_FALCO_SEVERITY_MAP = {
    "Emergency": "critical",
    "Alert":     "critical",
    "Critical":  "critical",
    "Error":     "high",
    "Warning":   "medium",
    "Notice":    "medium",
    "Informational": "low",
    "Debug":     "low",
}

# Map common Falco rules to MITRE ATT&CK techniques
_FALCO_RULE_TO_MITRE = {
    "Terminal shell in container":           "T1059",   # Command and Scripting Interpreter
    "Read sensitive file untrusted":         "T1552.001",  # Credentials In Files
    "Read sensitive file trusted after startup": "T1552.001",
    "Outbound Connection to C2 Servers":     "T1071",   # Application Layer Protocol
    "Disallowed SSH Connection":             "T1021.004",  # Remote Services: SSH
    "Mkdir binary dirs":                     "T1543",   # Create or Modify System Process
    "Write below binary dir":                "T1543",
    "Write below etc":                       "T1546",   # Event Triggered Execution
    "Modify binary dirs":                    "T1543",
    "Launch Privileged Container":           "T1611",   # Escape to Host
    "Launch Sensitive Mount Container":      "T1611",
    "Detect outbound connections to common miner pool ports": "T1496",  # Resource Hijacking
    "Crypto Miners":                         "T1496",
    "Container Drift Detected":              "T1611",
    "Netcat Remote Code Execution in Container": "T1059",
    "Suspicious network tool launched in container": "T1046",  # Network Service Scanning
    "Search Private Keys or Passwords":      "T1552",
    "User mgmt binaries":                    "T1098",   # Account Manipulation
    "Set Setuid or Setgid bit":              "T1548.001",  # Setuid and Setgid
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Embedded fallback events (sourced from Falco's OFFICIAL rules pack v0.37
# https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml).
# These are REAL Falco event format, with synthetic but plausible content.
# Used when no live cluster is reachable so the connector still demonstrates
# end-to-end ingestion behavior.
# ---------------------------------------------------------------------------
_FALCO_FALLBACK_EVENTS: List[Dict[str, Any]] = [
    {
        "rule":     "Terminal shell in container",
        "priority": "Notice",
        "output":   "A shell was spawned in a container with an attached terminal "
                    "(user=root user_loginuid=-1 container_id=ea99cd034083 "
                    "container_name=alpine-test shell=sh parent=runc cmdline=sh "
                    "terminal=34816)",
        "time":     "2026-04-25T19:23:11.123456Z",
        "output_fields": {
            "container.id":   "ea99cd034083",
            "container.name": "alpine-test",
            "proc.cmdline":   "sh",
            "proc.name":      "sh",
            "proc.pname":     "runc",
            "user.name":      "root",
        },
    },
    {
        "rule":     "Read sensitive file untrusted",
        "priority": "Warning",
        "output":   "Sensitive file opened for reading by non-trusted program "
                    "(file=/etc/shadow user=root program=cat command=cat /etc/shadow "
                    "container_id=ea99cd034083 container_name=alpine-test)",
        "time":     "2026-04-25T19:23:14.987654Z",
        "output_fields": {
            "container.id":   "ea99cd034083",
            "container.name": "alpine-test",
            "fd.name":        "/etc/shadow",
            "proc.cmdline":   "cat /etc/shadow",
            "proc.name":      "cat",
            "user.name":      "root",
        },
    },
    {
        "rule":     "Netcat Remote Code Execution in Container",
        "priority": "Critical",
        "output":   "Netcat runs inside container that allows remote code execution "
                    "(user=root command=nc -lvp 4444 container_id=ea99cd034083 "
                    "container_name=alpine-test)",
        "time":     "2026-04-25T19:23:18.555555Z",
        "output_fields": {
            "container.id":   "ea99cd034083",
            "container.name": "alpine-test",
            "proc.cmdline":   "nc -lvp 4444",
            "proc.name":      "nc",
            "user.name":      "root",
        },
    },
    {
        "rule":     "Suspicious network tool launched in container",
        "priority": "Notice",
        "output":   "Network tool launched in container (user=root command=nmap "
                    "-sS 10.96.0.0/12 container_id=ea99cd034083)",
        "time":     "2026-04-25T19:23:21.111111Z",
        "output_fields": {
            "container.id":   "ea99cd034083",
            "container.name": "alpine-test",
            "proc.cmdline":   "nmap -sS 10.96.0.0/12",
            "proc.name":      "nmap",
            "user.name":      "root",
        },
    },
    {
        "rule":     "Detect outbound connections to common miner pool ports",
        "priority": "Critical",
        "output":   "Outbound connection to common miner pool port "
                    "(command=xmrig --url=pool.minexmr.com:5555 "
                    "container_id=ea99cd034083 fd.sport=43210 fd.dport=5555 "
                    "fd.sip=10.244.0.5 fd.dip=199.83.131.31)",
        "time":     "2026-04-25T19:23:25.222222Z",
        "output_fields": {
            "container.id":   "ea99cd034083",
            "container.name": "alpine-test",
            "fd.dip":         "199.83.131.31",
            "fd.dport":       "5555",
            "proc.cmdline":   "xmrig --url=pool.minexmr.com:5555",
            "proc.name":      "xmrig",
            "user.name":      "root",
        },
    },
    {
        "rule":     "Write below etc",
        "priority": "Error",
        "output":   "File below /etc opened for writing (user=root command=tee "
                    "/etc/cron.d/backdoor file=/etc/cron.d/backdoor "
                    "container_id=ea99cd034083)",
        "time":     "2026-04-25T19:23:29.333333Z",
        "output_fields": {
            "container.id":   "ea99cd034083",
            "container.name": "alpine-test",
            "fd.name":        "/etc/cron.d/backdoor",
            "proc.cmdline":   "tee /etc/cron.d/backdoor",
            "proc.name":      "tee",
            "user.name":      "root",
        },
    },
]

# osquery snapshot result format (real schema from osquery v5+)
_OSQUERY_FALLBACK_EVENTS: List[Dict[str, Any]] = [
    {
        "name":       "pack_incident-response_processes",
        "hostIdentifier": "alpine-test.kind-aldeci-edr",
        "calendarTime":  "Sat Apr 25 19:23:11 2026 UTC",
        "unixTime":      1798874591,
        "epoch":         0,
        "counter":       0,
        "logNumericsAsNumbers": "false",
        "columns": {
            "pid":          "12345",
            "name":         "sh",
            "path":         "/bin/sh",
            "cmdline":      "sh",
            "cwd":          "/",
            "uid":          "0",
            "username":     "root",
            "parent":       "1",
            "start_time":   "1798874591",
        },
        "action":       "added",
    },
    {
        "name":       "pack_incident-response_logged_in_users",
        "hostIdentifier": "alpine-test.kind-aldeci-edr",
        "calendarTime":  "Sat Apr 25 19:23:15 2026 UTC",
        "unixTime":      1798874595,
        "columns": {
            "user":  "root",
            "tty":   "pts/0",
            "host":  "10.244.0.1",
            "time":  "1798874595",
            "pid":   "12345",
        },
        "action":       "added",
    },
]

# Wazuh alerts.json format (real schema from Wazuh 4.x manager)
_WAZUH_FALLBACK_EVENTS: List[Dict[str, Any]] = [
    {
        "timestamp":  "2026-04-25T19:23:11.000+0000",
        "rule": {
            "level":     12,
            "id":        "5402",
            "description": "Successful sudo to ROOT executed",
            "groups":    ["syslog", "sudo"],
            "mitre":     {"id": ["T1548.003"], "tactic": ["Privilege Escalation"]},
        },
        "agent":      {"id": "001", "name": "alpine-test", "ip": "10.244.0.5"},
        "manager":    {"name": "wazuh-manager"},
        "id":         "1798874591.123456",
        "full_log":   "Apr 25 19:23:11 alpine-test sudo: root : TTY=pts/0 ; PWD=/ ; "
                      "USER=root ; COMMAND=/bin/sh",
        "data": {
            "srcuser":  "root",
            "dstuser":  "root",
            "tty":      "pts/0",
            "command":  "/bin/sh",
        },
    },
    {
        "timestamp":  "2026-04-25T19:23:18.000+0000",
        "rule": {
            "level":    14,
            "id":       "100200",
            "description": "Suspicious network listener detected (nc -lvp 4444)",
            "groups":   ["network", "intrusion_detection"],
            "mitre":    {"id": ["T1571"], "tactic": ["Command and Control"]},
        },
        "agent":      {"id": "001", "name": "alpine-test", "ip": "10.244.0.5"},
        "id":         "1798874598.987654",
        "full_log":   "tcp 0.0.0.0:4444 LISTEN nc",
        "data":       {"srcip": "0.0.0.0", "srcport": "4444", "process": "nc"},
    },
]


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------
def _falco_to_edr_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a Falco JSON event into the EDREngine ingest_process_event schema."""
    fields = raw.get("output_fields") or {}
    rule = raw.get("rule", "Unknown rule")
    proc_name = fields.get("proc.name") or ""
    cmdline = fields.get("proc.cmdline") or ""
    user = fields.get("user.name") or ""
    parent = fields.get("proc.pname") or ""
    severity = _FALCO_SEVERITY_MAP.get(raw.get("priority", "Notice"), "medium")
    mitre = _FALCO_RULE_TO_MITRE.get(rule, "")
    return {
        "process_name":   proc_name,
        "process_hash":   "",
        "parent_process": parent,
        "cmdline":        cmdline,
        "user":           user,
        "pid":            0,
        "event_type":     "create",
        "severity":       severity,
        "mitre_technique": mitre,
        # Carry the raw rule for finding correlation
        "_falco_rule":    rule,
        "_falco_output":  raw.get("output", ""),
        "_container_id":  fields.get("container.id", ""),
        "_container_name": fields.get("container.name", ""),
    }


def _osquery_to_edr_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an osquery snapshot record to EDR ingest format."""
    cols = raw.get("columns") or {}
    cmdline = cols.get("cmdline") or cols.get("command") or ""
    proc_name = cols.get("name") or ""
    pid_raw = cols.get("pid") or "0"
    try:
        pid = int(pid_raw)
    except (ValueError, TypeError):
        pid = 0
    return {
        "process_name":   proc_name,
        "process_hash":   "",
        "parent_process": cols.get("parent") or "",
        "cmdline":        cmdline,
        "user":           cols.get("username") or cols.get("user") or "",
        "pid":            pid,
        "event_type":     "create",
        "severity":       "info",
        "mitre_technique": "",
        "_osquery_pack":  raw.get("name", ""),
        "_host_id":       raw.get("hostIdentifier", ""),
    }


def _wazuh_to_edr_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a Wazuh alert into EDR ingest format."""
    rule = raw.get("rule") or {}
    data = raw.get("data") or {}
    level = int(rule.get("level", 0))
    if level >= 13:
        severity = "critical"
    elif level >= 10:
        severity = "high"
    elif level >= 7:
        severity = "medium"
    else:
        severity = "low"
    mitre_ids = (rule.get("mitre") or {}).get("id") or [""]
    return {
        "process_name":   data.get("process", "") or "wazuh_alert",
        "process_hash":   "",
        "parent_process": "",
        "cmdline":        data.get("command", "") or raw.get("full_log", "")[:200],
        "user":           data.get("srcuser", "") or data.get("dstuser", ""),
        "pid":            0,
        "event_type":     "suspicious_api",
        "severity":       severity,
        "mitre_technique": mitre_ids[0] if mitre_ids else "",
        "_wazuh_rule_id": rule.get("id", ""),
        "_wazuh_desc":    rule.get("description", ""),
    }


# ---------------------------------------------------------------------------
# EDRConnector
# ---------------------------------------------------------------------------
class EDRConnector:
    """Real EDR/XDR connector — Falco + osquery + Wazuh federation.

    Args:
        edr_engine:        instance of core.edr_engine.EDREngine
        findings_engine:   instance of core.security_findings_engine.SecurityFindingsEngine
        kube_context:      kubectl context name for live Falco tail
                           (default 'kind-aldeci-edr')
        falco_namespace:   namespace where Falco runs (default 'falco')
        kubectl_path:      override kubectl binary path (autodetected)
    """

    def __init__(
        self,
        edr_engine: Any,
        findings_engine: Any,
        correlation_engine: Any = None,
        kube_context: str = "kind-aldeci-edr",
        falco_namespace: str = "falco",
        kubectl_path: Optional[str] = None,
    ) -> None:
        self._edr = edr_engine
        self._findings = findings_engine
        self._correlation = correlation_engine
        self._kube_context = kube_context
        self._falco_ns = falco_namespace
        self._kubectl = kubectl_path or shutil.which("kubectl") or "kubectl"
        self._lock = threading.RLock()

    def _mirror_correlation(
        self,
        org_id: str,
        source_system: str,
        event_type: str,
        severity: str,
        entity_id: str,
        entity_type: str,
        raw: Dict[str, Any],
    ) -> None:
        """Mirror an event to security_event_correlation_engine for cross-domain rules."""
        if not self._correlation:
            return
        # Correlation engine valid severities: critical/high/medium/low/info
        sev = severity if severity in {"critical", "high", "medium", "low", "info"} else "medium"
        try:
            self._correlation.ingest_event(
                org_id,
                {
                    "source_system": source_system,
                    "event_type": event_type,
                    "severity": sev,
                    "entity_id": entity_id,
                    "entity_type": entity_type,
                    "raw_data": raw,
                },
            )
        except (ValueError, TypeError, AttributeError) as exc:
            _logger.warning("correlation mirror failed for %s: %s", source_system, exc)

    # ------------------------------------------------------------------
    # Endpoint registration
    # ------------------------------------------------------------------
    def _ensure_endpoint(
        self,
        org_id: str,
        hostname: str,
        agent: str,
    ) -> str:
        """Find or create an endpoint record. Returns endpoint_id."""
        for ep in self._edr.list_endpoints(org_id):
            if ep.get("hostname") == hostname:
                return ep["endpoint_id"]
        rec = self._edr.register_endpoint(
            org_id,
            {
                "hostname":      hostname,
                "ip_address":    "",
                "os_type":       "linux",
                "os_version":    "kind-node-1.35",
                "agent_version": agent,
            },
        )
        return rec["endpoint_id"]

    # ------------------------------------------------------------------
    # Falco — live or fallback
    # ------------------------------------------------------------------
    def _read_falco_live(self, max_lines: int = 200) -> List[Dict[str, Any]]:
        """Tail the Falco DaemonSet logs and parse JSON events.

        Returns an empty list on any failure (caller falls back).
        """
        try:
            proc = subprocess.run(
                [
                    self._kubectl, "--context", self._kube_context,
                    "logs", "-n", self._falco_ns,
                    "daemonset/falco",
                    f"--tail={max_lines}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            _logger.warning("Falco live tail failed: %s — using fallback events", exc)
            return []
        if proc.returncode != 0:
            _logger.warning(
                "kubectl logs returned %s: %s — using fallback events",
                proc.returncode, (proc.stderr or "")[:200],
            )
            return []
        events: List[Dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if "rule" in obj and "priority" in obj:
                events.append(obj)
        return events

    def sync_from_falco(
        self,
        org_id: str,
        hostname: str = "kind-aldeci-edr-control-plane",
        max_events: int = 10,
        force_fallback: bool = False,
    ) -> Dict[str, Any]:
        """Sync EDR events from Falco. Live-first, fallback to embedded samples.

        Returns: {source, events_ingested, detections_created, findings_recorded,
                  endpoint_id, mode: 'live'|'fallback'}
        """
        events: List[Dict[str, Any]] = []
        mode = "live"
        if not force_fallback:
            events = self._read_falco_live(max_lines=max_events * 5)
        if not events:
            mode = "fallback"
            events = list(_FALCO_FALLBACK_EVENTS[:max_events])

        endpoint_id = self._ensure_endpoint(org_id, hostname, agent="falco-via-edr-connector")
        ingested = 0
        findings = 0
        with self._lock:
            for raw in events:
                norm = _falco_to_edr_event(raw)
                falco_rule = norm.pop("_falco_rule", "Unknown")
                falco_output = norm.pop("_falco_output", "")
                container_id = norm.pop("_container_id", "")
                norm.pop("_container_name", "")
                try:
                    self._edr.ingest_process_event(org_id, endpoint_id, norm)
                    ingested += 1
                except (ValueError, TypeError) as exc:
                    _logger.warning("EDR ingest failed for %s: %s", falco_rule, exc)
                    continue
                # Mirror to SecurityFindingsEngine as source_tool=edr_via_falco
                try:
                    cvss = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0}
                    self._findings.record_finding(
                        org_id=org_id,
                        title=f"Falco: {falco_rule}",
                        finding_type="anomaly",
                        source_tool="EDR",  # canonical bucket; actual tool in correlation_key
                        severity=norm["severity"] if norm["severity"] != "info" else "low",
                        cvss_score=cvss.get(norm["severity"], 3.0),
                        asset_id=container_id or hostname,
                        asset_type="container" if container_id else "host",
                        description=falco_output[:500],
                        remediation=(
                            "Investigate the alert in the SOC console; "
                            "isolate the container if confirmed malicious."
                        ),
                        correlation_key=f"falco|{falco_rule}|{container_id or hostname}",
                    )
                    findings += 1
                except (ValueError, TypeError) as exc:
                    _logger.warning("Finding record failed: %s", exc)
                self._mirror_correlation(
                    org_id=org_id,
                    source_system="falco",
                    event_type="runtime_alert",
                    severity=norm["severity"] if norm["severity"] != "info" else "low",
                    entity_id=container_id or hostname,
                    entity_type="container" if container_id else "host",
                    raw={"rule": falco_rule, "output": falco_output, "cmdline": norm.get("cmdline")},
                )
        emit_connector_event(
            connector="EDRConnector",
            org_id=org_id,
            source_kind="edr",
            finding_count=findings,
            extra={"source": "falco", "mode": mode, "endpoint_id": endpoint_id, "events_ingested": ingested},
        )
        return {
            "source":             "falco",
            "mode":               mode,
            "events_ingested":    ingested,
            "findings_recorded":  findings,
            "endpoint_id":        endpoint_id,
            "endpoint_hostname":  hostname,
            "events_processed":   len(events),
        }

    # ------------------------------------------------------------------
    # osquery — file-based or fallback
    # ------------------------------------------------------------------
    def sync_from_osquery(
        self,
        org_id: str,
        log_file: Optional[str] = None,
        max_events: int = 10,
    ) -> Dict[str, Any]:
        """Sync events from an osquery JSON log file (snapshot results).

        Falls back to embedded samples if the file is absent / unreadable.
        """
        events: List[Dict[str, Any]] = []
        mode = "fallback"
        if log_file:
            log_path = Path(log_file)
            if log_path.is_file():
                try:
                    with log_path.open("r", encoding="utf-8") as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                events.append(json.loads(line))
                            except (json.JSONDecodeError, ValueError):
                                continue
                            if len(events) >= max_events:
                                break
                    if events:
                        mode = "live"
                except OSError as exc:
                    _logger.warning("osquery log read failed: %s", exc)
        if not events:
            events = list(_OSQUERY_FALLBACK_EVENTS[:max_events])

        ingested = 0
        findings = 0
        with self._lock:
            for raw in events:
                host = raw.get("hostIdentifier") or "osquery-host"
                endpoint_id = self._ensure_endpoint(org_id, host, agent="osquery-via-edr-connector")
                norm = _osquery_to_edr_event(raw)
                pack = norm.pop("_osquery_pack", "")
                norm.pop("_host_id", None)
                try:
                    self._edr.ingest_process_event(org_id, endpoint_id, norm)
                    ingested += 1
                except (ValueError, TypeError) as exc:
                    _logger.warning("osquery ingest failed: %s", exc)
                    continue
                try:
                    self._findings.record_finding(
                        org_id=org_id,
                        title=f"osquery: {pack or 'process_observed'}",
                        finding_type="anomaly",
                        source_tool="EDR",
                        severity="low",
                        cvss_score=2.0,
                        asset_id=host,
                        asset_type="host",
                        description=f"osquery snapshot: process={norm.get('process_name')} "
                                    f"cmd={norm.get('cmdline')} user={norm.get('user')}",
                        remediation="Correlate with EDR detections and SIEM.",
                        correlation_key=f"osquery|{pack}|{host}|{norm.get('process_name')}",
                    )
                    findings += 1
                except (ValueError, TypeError) as exc:
                    _logger.warning("osquery finding record failed: %s", exc)
                self._mirror_correlation(
                    org_id=org_id,
                    source_system="osquery",
                    event_type="process_observed",
                    severity="info",
                    entity_id=host,
                    entity_type="host",
                    raw={"pack": pack, "process": norm.get("process_name"), "cmdline": norm.get("cmdline"), "user": norm.get("user")},
                )
        emit_connector_event(
            connector="EDRConnector",
            org_id=org_id,
            source_kind="edr",
            finding_count=findings,
            extra={"source": "osquery", "mode": mode, "events_ingested": ingested},
        )
        return {
            "source": "osquery",
            "mode":   mode,
            "events_ingested":   ingested,
            "findings_recorded": findings,
            "events_processed":  len(events),
        }

    # ------------------------------------------------------------------
    # Wazuh — file-based or fallback
    # ------------------------------------------------------------------
    def sync_from_wazuh(
        self,
        org_id: str,
        alerts_file: Optional[str] = None,
        max_events: int = 10,
    ) -> Dict[str, Any]:
        """Sync alerts from a Wazuh manager alerts.json file.

        Falls back to embedded samples if the file is absent / unreadable.
        """
        events: List[Dict[str, Any]] = []
        mode = "fallback"
        if alerts_file:
            ap = Path(alerts_file)
            if ap.is_file():
                try:
                    with ap.open("r", encoding="utf-8") as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                events.append(json.loads(line))
                            except (json.JSONDecodeError, ValueError):
                                continue
                            if len(events) >= max_events:
                                break
                    if events:
                        mode = "live"
                except OSError as exc:
                    _logger.warning("Wazuh alerts read failed: %s", exc)
        if not events:
            events = list(_WAZUH_FALLBACK_EVENTS[:max_events])

        ingested = 0
        findings = 0
        with self._lock:
            for raw in events:
                agent = raw.get("agent") or {}
                host = agent.get("name") or "wazuh-host"
                endpoint_id = self._ensure_endpoint(org_id, host, agent="wazuh-via-edr-connector")
                norm = _wazuh_to_edr_event(raw)
                rule_id = norm.pop("_wazuh_rule_id", "")
                desc = norm.pop("_wazuh_desc", "")
                try:
                    self._edr.ingest_process_event(org_id, endpoint_id, norm)
                    ingested += 1
                except (ValueError, TypeError) as exc:
                    _logger.warning("Wazuh ingest failed: %s", exc)
                    continue
                try:
                    cvss = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0}
                    self._findings.record_finding(
                        org_id=org_id,
                        title=f"Wazuh rule {rule_id}: {desc[:80]}",
                        finding_type="anomaly",
                        source_tool="SIEM",  # Wazuh is a HIDS+SIEM
                        severity=norm["severity"],
                        cvss_score=cvss.get(norm["severity"], 4.0),
                        asset_id=host,
                        asset_type="host",
                        description=raw.get("full_log", "")[:500] or desc,
                        remediation="Triage Wazuh alert; correlate with EDR/XDR.",
                        correlation_key=f"wazuh|{rule_id}|{host}",
                    )
                    findings += 1
                except (ValueError, TypeError) as exc:
                    _logger.warning("Wazuh finding record failed: %s", exc)
                self._mirror_correlation(
                    org_id=org_id,
                    source_system="wazuh",
                    event_type="hids_alert",
                    severity=norm["severity"],
                    entity_id=host,
                    entity_type="host",
                    raw={"rule_id": rule_id, "description": desc, "full_log": raw.get("full_log", "")[:500]},
                )
        emit_connector_event(
            connector="EDRConnector",
            org_id=org_id,
            source_kind="siem",
            finding_count=findings,
            extra={"source": "wazuh", "mode": mode, "events_ingested": ingested},
        )
        return {
            "source": "wazuh",
            "mode":   mode,
            "events_ingested":   ingested,
            "findings_recorded": findings,
            "events_processed":  len(events),
        }

    # ------------------------------------------------------------------
    # Multi-tenant fan-out
    # ------------------------------------------------------------------
    def sync_all_tenants(
        self,
        org_ids: Iterable[str],
        events_per_org: int = 4,
        force_fallback: bool = True,
    ) -> Dict[str, Any]:
        """Synthesize 3-5 EDR-style alerts per tenant, attributed to that org.

        Used for demos to populate the dashboard for every tenant simultaneously.
        Returns {org_id: result_dict}.
        """
        events_per_org = max(3, min(5, events_per_org))
        out: Dict[str, Any] = {}
        for org in org_ids:
            falco_res = self.sync_from_falco(
                org_id=org,
                hostname=f"endpoint-{org}",
                max_events=events_per_org,
                force_fallback=force_fallback,
            )
            osquery_res = self.sync_from_osquery(org_id=org, max_events=2)
            wazuh_res = self.sync_from_wazuh(org_id=org, max_events=2)
            out[org] = {
                "falco":   falco_res,
                "osquery": osquery_res,
                "wazuh":   wazuh_res,
                "total_findings": (
                    falco_res["findings_recorded"]
                    + osquery_res["findings_recorded"]
                    + wazuh_res["findings_recorded"]
                ),
            }
        return out


# ---------------------------------------------------------------------------
# Module-level singleton accessor (lazy)
# ---------------------------------------------------------------------------
_singleton_lock = threading.Lock()
_singleton: Optional[EDRConnector] = None


def get_edr_connector() -> EDRConnector:
    """Lazy singleton — wires EDREngine + SecurityFindingsEngine + correlation on first use."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            from core.edr_engine import EDREngine
            from core.security_findings_engine import SecurityFindingsEngine
            try:
                from core.security_event_correlation_engine import (
                    SecurityEventCorrelationEngine,
                )
                corr = SecurityEventCorrelationEngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("correlation engine unavailable: %s", exc)
                corr = None
            _singleton = EDRConnector(
                edr_engine=EDREngine(),
                findings_engine=SecurityFindingsEngine(),
                correlation_engine=corr,
            )
        return _singleton


__all__ = [
    "EDRConnector",
    "get_edr_connector",
    "_FALCO_FALLBACK_EVENTS",
    "_OSQUERY_FALLBACK_EVENTS",
    "_WAZUH_FALLBACK_EVENTS",
]
