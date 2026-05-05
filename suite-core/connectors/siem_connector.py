"""SIEM Connector — multi-format SIEM ingest adapters for ALDECI.

Provides parser/normalizer adapters that translate vendor-native log
formats into a common ALDECI event envelope, then forwards to:
  - SIEMIntegrationEngine (siem_source_events)
  - SecurityEventCorrelationEngine (security_events)
  - SecurityFindingsEngine (security_findings, when severity >= medium)

OSS replacements for proprietary SIEMs:
  - Splunk         -> Wazuh server (open-source SIEM)
  - Datadog        -> Wazuh + Suricata + Vector
  - Sentinel       -> ELK (Elasticsearch + Logstash + Kibana)
  - QRadar         -> Wazuh + alert correlator
  - Elastic SIEM   -> Elastic free SIEM (already OSS)
  - Wazuh          -> native (alerts.json)
  - Suricata       -> native (eve.json)

Supported input formats:
  - splunk_hec      Splunk HTTP Event Collector envelope
  - datadog         Datadog Logs Intake API JSON
  - sentinel_kql    Microsoft Sentinel KQL result set
  - elk_bulk        Elasticsearch _bulk newline-delimited JSON
  - cef             ArcSight Common Event Format (used by QRadar)
  - syslog          RFC 3164 / 5424 (Wazuh, generic)
  - wazuh_alert     Wazuh alerts.json record
  - suricata_eve    Suricata eve.json record
  - json_lines      Generic JSON-lines event
  - auto            Detect from envelope shape

Each adapter returns a NormalizedEvent dict:
  {
    "source_system":  str,   # splunk | datadog | sentinel | elk | qradar | wazuh | suricata
    "event_type":     str,   # auth | network | endpoint | application | k8s
    "severity":       str,   # critical | high | medium | low | info
    "source_ip":      str,
    "destination_ip": str,
    "user":           str,
    "host":           str,
    "message":        str,
    "timestamp":      str,   # ISO 8601
    "raw":            dict,  # original record
  }
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from connectors._emit import emit_connector_event

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# Numeric -> ALDECI severity (CEF / Suricata / generic 0-10 scales)
_NUM_SEV = {
    0: "info", 1: "info", 2: "info", 3: "low",
    4: "low", 5: "medium", 6: "medium", 7: "high",
    8: "high", 9: "critical", 10: "critical",
}

# Wazuh rule levels: 0-15
_WAZUH_LEVEL = {
    **{i: "info" for i in range(0, 4)},
    **{i: "low" for i in range(4, 7)},
    **{i: "medium" for i in range(7, 10)},
    **{i: "high" for i in range(10, 13)},
    **{i: "critical" for i in range(13, 16)},
}

_TEXT_SEV = {
    "emerg": "critical", "emergency": "critical", "alert": "critical",
    "crit": "critical", "critical": "critical", "fatal": "critical",
    "err": "high", "error": "high", "high": "high", "severe": "high",
    "warn": "medium", "warning": "medium", "notice": "medium",
    "medium": "medium", "moderate": "medium",
    "low": "low", "info": "info", "informational": "info",
    "debug": "info", "trace": "info",
}


def normalize_severity(raw: Any) -> str:
    """Coerce any severity input into one of the 5 ALDECI levels."""
    if raw is None:
        return "info"
    if isinstance(raw, (int, float)):
        return _NUM_SEV.get(int(round(raw)), "info")
    s = str(raw).strip().lower()
    if not s:
        return "info"
    if s in _VALID_SEVERITIES:
        return s
    if s in _TEXT_SEV:
        return _TEXT_SEV[s]
    if s.isdigit():
        return _NUM_SEV.get(int(s), "info")
    return "info"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_str(v: Any) -> str:
    return "" if v is None else str(v)


# ---------------------------------------------------------------------------
# Base adapter
# ---------------------------------------------------------------------------


class BaseSIEMAdapter:
    """Base class for SIEM input adapters."""

    source_system: str = "generic"

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        """Return a list of NormalizedEvent dicts."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Splunk HEC
# ---------------------------------------------------------------------------


class SplunkHECAdapter(BaseSIEMAdapter):
    """Parses Splunk HEC envelope.

    Splunk HEC payload:
      {"event": {...} | "<text>", "time": <epoch>, "host": "...",
       "source": "...", "sourcetype": "...", "index": "...", "fields": {...}}
    Multiple events may be concatenated as newline-delimited JSON.
    """

    source_system = "splunk"

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        records = self._iter_records(payload)
        out: List[Dict[str, Any]] = []
        for rec in records:
            evt = rec.get("event", rec)
            if isinstance(evt, str):
                evt = {"message": evt}
            elif not isinstance(evt, dict):
                evt = {"message": str(evt)}
            ts = self._parse_time(rec.get("time")) or _now_iso()
            sourcetype = _safe_str(rec.get("sourcetype")).lower()
            fields = rec.get("fields") or {}
            out.append({
                "source_system": self.source_system,
                "event_type": self._classify(sourcetype, evt),
                "severity": normalize_severity(
                    evt.get("severity") or evt.get("level") or fields.get("severity")
                ),
                "source_ip": _safe_str(evt.get("src") or evt.get("src_ip") or evt.get("source_ip")),
                "destination_ip": _safe_str(evt.get("dest") or evt.get("dest_ip") or evt.get("destination_ip")),
                "user": _safe_str(evt.get("user") or evt.get("src_user")),
                "host": _safe_str(rec.get("host") or evt.get("host")),
                "message": _safe_str(evt.get("message") or evt.get("_raw") or evt.get("msg")),
                "timestamp": ts,
                "raw": rec,
            })
        return out

    @staticmethod
    def _iter_records(payload: Any) -> Iterable[Dict[str, Any]]:
        if isinstance(payload, list):
            for r in payload:
                if isinstance(r, dict):
                    yield r
            return
        if isinstance(payload, dict):
            yield payload
            return
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8", errors="replace")
        if isinstance(payload, str):
            for line in payload.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    yield {"event": {"message": line}, "time": None}

    @staticmethod
    def _parse_time(t: Any) -> Optional[str]:
        if t in (None, "", 0):
            return None
        try:
            if isinstance(t, (int, float)):
                return datetime.fromtimestamp(float(t), tz=timezone.utc).isoformat()
            return str(t)
        except (ValueError, OSError, TypeError):
            return None

    @staticmethod
    def _classify(sourcetype: str, evt: Dict[str, Any]) -> str:
        st = sourcetype or ""
        msg = _safe_str(evt.get("message") or evt.get("_raw")).lower()
        if (
            "auth" in st or "wineventlog" in st or "secure" in st
            or "sshd" in msg or "logon" in msg or "login" in msg
            or "failed password" in msg or "accepted password" in msg
            or "sudo" in msg
        ):
            return "auth"
        if "access" in st or "nginx" in st or "apache" in st or "http" in st:
            return "application"
        if "firewall" in st or "netflow" in st or "pcap" in st:
            return "network"
        if "sysmon" in st or "endpoint" in st or "edr" in st:
            return "endpoint"
        return "application"


# ---------------------------------------------------------------------------
# Datadog Logs API
# ---------------------------------------------------------------------------


class DatadogAdapter(BaseSIEMAdapter):
    """Parses Datadog Logs Intake API payload.

    Datadog payload (POST /api/v2/logs):
      [{"ddsource": "...", "ddtags": "...", "hostname": "...",
        "service": "...", "message": "...", "status": "...",
        "timestamp": "...", "<custom>": ...}, ...]
    """

    source_system = "datadog"

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        records = payload if isinstance(payload, list) else [payload]
        out: List[Dict[str, Any]] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            ts = rec.get("timestamp") or _now_iso()
            tags = self._tags_to_dict(rec.get("ddtags", ""))
            ddsource = _safe_str(rec.get("ddsource")).lower()
            out.append({
                "source_system": self.source_system,
                "event_type": self._classify(ddsource, rec, tags),
                "severity": normalize_severity(
                    rec.get("status") or rec.get("level") or tags.get("severity")
                ),
                "source_ip": _safe_str(
                    rec.get("network.client.ip")
                    or rec.get("source_ip")
                    or tags.get("src")
                ),
                "destination_ip": _safe_str(
                    rec.get("network.destination.ip")
                    or rec.get("destination_ip")
                ),
                "user": _safe_str(rec.get("usr.name") or rec.get("user")),
                "host": _safe_str(rec.get("hostname") or rec.get("host")),
                "message": _safe_str(rec.get("message")),
                "timestamp": _safe_str(ts),
                "raw": rec,
            })
        return out

    @staticmethod
    def _tags_to_dict(tags: Any) -> Dict[str, str]:
        if isinstance(tags, dict):
            return {str(k): str(v) for k, v in tags.items()}
        if not isinstance(tags, str):
            return {}
        out: Dict[str, str] = {}
        for tag in tags.split(","):
            tag = tag.strip()
            if not tag:
                continue
            if ":" in tag:
                k, _, v = tag.partition(":")
                out[k] = v
            else:
                out[tag] = "1"
        return out

    @staticmethod
    def _classify(ddsource: str, rec: Dict[str, Any], tags: Dict[str, str]) -> str:
        s = ddsource or _safe_str(tags.get("source")).lower()
        if s in {"ssh", "sshd", "auth", "windows", "wineventlog"}:
            return "auth"
        if s in {"nginx", "apache", "http", "python", "java", "node", "rails"}:
            return "application"
        if s in {"suricata", "zeek", "firewall", "vpc", "netflow"}:
            return "network"
        if s in {"sysmon", "osquery", "crowdstrike", "sentinelone"}:
            return "endpoint"
        if s in {"kubernetes", "k8s"}:
            return "k8s"
        return "application"


# ---------------------------------------------------------------------------
# Microsoft Sentinel KQL output
# ---------------------------------------------------------------------------


class SentinelKQLAdapter(BaseSIEMAdapter):
    """Parses Microsoft Sentinel KQL result set.

    KQL JSON output:
      {"tables": [{"name": "PrimaryResult",
                   "columns": [{"name": "...", "type": "..."}, ...],
                   "rows": [[...], ...]}]}

    Common Sentinel tables: SecurityAlert, SigninLogs, AuditLogs,
    CommonSecurityLog, SecurityEvent, AzureActivity.
    """

    source_system = "sentinel"

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        tables = payload.get("tables") or []
        out: List[Dict[str, Any]] = []
        for table in tables:
            if not isinstance(table, dict):
                continue
            cols = [c.get("name") for c in (table.get("columns") or []) if isinstance(c, dict)]
            for row in table.get("rows") or []:
                if not isinstance(row, list):
                    continue
                rec = dict(zip(cols, row))
                table_name = _safe_str(table.get("name")).lower()
                ts = (
                    rec.get("TimeGenerated")
                    or rec.get("EventTime")
                    or rec.get("Timestamp")
                    or _now_iso()
                )
                sev_raw = (
                    rec.get("AlertSeverity")
                    or rec.get("Severity")
                    or rec.get("LogLevel")
                )
                out.append({
                    "source_system": self.source_system,
                    "event_type": self._classify(table_name, rec),
                    "severity": normalize_severity(sev_raw),
                    "source_ip": _safe_str(
                        rec.get("IPAddress")
                        or rec.get("SourceIP")
                        or rec.get("CallerIpAddress")
                    ),
                    "destination_ip": _safe_str(
                        rec.get("DestinationIP")
                        or rec.get("TargetIP")
                    ),
                    "user": _safe_str(
                        rec.get("UserPrincipalName")
                        or rec.get("AccountName")
                        or rec.get("UserId")
                    ),
                    "host": _safe_str(
                        rec.get("Computer")
                        or rec.get("DeviceName")
                        or rec.get("Resource")
                    ),
                    "message": _safe_str(
                        rec.get("AlertName")
                        or rec.get("DisplayName")
                        or rec.get("Description")
                        or rec.get("Activity")
                    ),
                    "timestamp": _safe_str(ts),
                    "raw": rec,
                })
        return out

    @staticmethod
    def _classify(table: str, rec: Dict[str, Any]) -> str:
        t = table or ""
        if "signin" in t or "auth" in t or "securityevent" in t:
            return "auth"
        if "common" in t or "securityalert" in t:
            return "endpoint"
        if "audit" in t or "azureactivity" in t:
            return "application"
        return "application"


# ---------------------------------------------------------------------------
# Elastic _bulk
# ---------------------------------------------------------------------------


class ELKBulkAdapter(BaseSIEMAdapter):
    """Parses Elasticsearch _bulk newline-delimited JSON.

    _bulk format alternates action and document lines:
      {"index": {"_index": "...", "_id": "..."}}
      {"@timestamp": "...", "host": {...}, "user": {...}, "event": {...}, ...}
      {"create": ...}
      {...}

    Documents follow ECS (Elastic Common Schema).
    """

    source_system = "elk"

    _ACTION_KEYS = {"index", "create", "update", "delete"}

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8", errors="replace")
        if isinstance(payload, list):
            # Already-parsed documents; treat each as a doc.
            docs = [d for d in payload if isinstance(d, dict)]
        elif isinstance(payload, str):
            docs = self._extract_docs(payload)
        elif isinstance(payload, dict):
            docs = [payload]
        else:
            return []
        out: List[Dict[str, Any]] = []
        for doc in docs:
            event = doc.get("event") or {}
            host = doc.get("host") or {}
            user = doc.get("user") or {}
            source = doc.get("source") or {}
            destination = doc.get("destination") or {}
            log = doc.get("log") or {}
            kind = _safe_str(event.get("category")).lower() if isinstance(event, dict) else ""
            severity = normalize_severity(
                event.get("severity") if isinstance(event, dict) else None
                or log.get("level") if isinstance(log, dict) else None
                or doc.get("severity")
            )
            out.append({
                "source_system": self.source_system,
                "event_type": self._classify(kind),
                "severity": severity,
                "source_ip": _safe_str(source.get("ip") if isinstance(source, dict) else ""),
                "destination_ip": _safe_str(destination.get("ip") if isinstance(destination, dict) else ""),
                "user": _safe_str(user.get("name") if isinstance(user, dict) else ""),
                "host": _safe_str(host.get("name") if isinstance(host, dict) else (host if isinstance(host, str) else "")),
                "message": _safe_str(doc.get("message") or (event.get("action") if isinstance(event, dict) else "")),
                "timestamp": _safe_str(doc.get("@timestamp") or _now_iso()),
                "raw": doc,
            })
        return out

    def _extract_docs(self, payload: str) -> List[Dict[str, Any]]:
        docs: List[Dict[str, Any]] = []
        skip_next = False
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if skip_next:
                skip_next = False
                continue
            if isinstance(obj, dict) and len(obj) == 1 and next(iter(obj.keys())) in self._ACTION_KEYS:
                # action header: next line is a doc (unless action is delete)
                action = next(iter(obj.keys()))
                if action == "delete":
                    continue
                # The next non-empty line is the document.
                continue
            if isinstance(obj, dict):
                docs.append(obj)
        return docs

    @staticmethod
    def _classify(category: str) -> str:
        if category in {"authentication", "iam"}:
            return "auth"
        if category in {"network", "intrusion_detection"}:
            return "network"
        if category in {"process", "host", "file", "malware"}:
            return "endpoint"
        return "application"


# ---------------------------------------------------------------------------
# Wazuh alerts
# ---------------------------------------------------------------------------


class WazuhAdapter(BaseSIEMAdapter):
    """Parses Wazuh alerts.json record.

    Wazuh alert structure (ossec.log / alerts.json):
      {"timestamp": "...", "rule": {"level": 5, "description": "...", "id": "..."},
       "agent": {"id": "...", "name": "...", "ip": "..."},
       "manager": {...}, "data": {"srcip": "...", "dstuser": "..."},
       "predecoder": {...}, "decoder": {...}, "full_log": "..."}
    """

    source_system = "wazuh"

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        records = payload if isinstance(payload, list) else [payload]
        out: List[Dict[str, Any]] = []
        for rec in records:
            if isinstance(rec, str):
                try:
                    rec = json.loads(rec)
                except (json.JSONDecodeError, ValueError):
                    continue
            if not isinstance(rec, dict):
                continue
            rule = rec.get("rule") or {}
            agent = rec.get("agent") or {}
            data = rec.get("data") or {}
            level = rule.get("level") if isinstance(rule, dict) else None
            sev = _WAZUH_LEVEL.get(int(level), "info") if isinstance(level, (int, float, str)) and str(level).isdigit() else normalize_severity(level)
            out.append({
                "source_system": self.source_system,
                "event_type": self._classify(rule, data),
                "severity": sev,
                "source_ip": _safe_str(data.get("srcip") or data.get("src_ip") if isinstance(data, dict) else ""),
                "destination_ip": _safe_str(data.get("dstip") if isinstance(data, dict) else ""),
                "user": _safe_str(data.get("dstuser") or data.get("srcuser") if isinstance(data, dict) else ""),
                "host": _safe_str(agent.get("name") or agent.get("ip") if isinstance(agent, dict) else ""),
                "message": _safe_str(
                    (rule.get("description") if isinstance(rule, dict) else "")
                    or rec.get("full_log")
                ),
                "timestamp": _safe_str(rec.get("timestamp") or _now_iso()),
                "raw": rec,
            })
        return out

    @staticmethod
    def _classify(rule: Any, data: Any) -> str:
        groups = []
        if isinstance(rule, dict):
            g = rule.get("groups") or []
            if isinstance(g, list):
                groups = [str(x).lower() for x in g]
        for kw in groups:
            if "auth" in kw or "ssh" in kw or "sudo" in kw:
                return "auth"
            if "firewall" in kw or "ids" in kw or "ips" in kw:
                return "network"
            if "syscheck" in kw or "rootcheck" in kw or "malware" in kw:
                return "endpoint"
        return "application"


# ---------------------------------------------------------------------------
# Suricata eve.json
# ---------------------------------------------------------------------------


class SuricataAdapter(BaseSIEMAdapter):
    """Parses Suricata eve.json records.

    Suricata event_type values: alert, http, dns, tls, flow, ssh, fileinfo.
    """

    source_system = "suricata"

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8", errors="replace")
        if isinstance(payload, str):
            recs = []
            for line in payload.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue
        elif isinstance(payload, list):
            recs = [r for r in payload if isinstance(r, dict)]
        elif isinstance(payload, dict):
            recs = [payload]
        else:
            return []
        out: List[Dict[str, Any]] = []
        for rec in recs:
            etype = _safe_str(rec.get("event_type")).lower()
            alert = rec.get("alert") or {}
            sev = normalize_severity(alert.get("severity") if isinstance(alert, dict) else "info")
            out.append({
                "source_system": self.source_system,
                "event_type": self._classify(etype),
                "severity": sev,
                "source_ip": _safe_str(rec.get("src_ip")),
                "destination_ip": _safe_str(rec.get("dest_ip")),
                "user": "",
                "host": _safe_str(rec.get("host", "")),
                "message": _safe_str(
                    alert.get("signature") if isinstance(alert, dict) else f"suricata {etype}"
                ),
                "timestamp": _safe_str(rec.get("timestamp") or _now_iso()),
                "raw": rec,
            })
        return out

    @staticmethod
    def _classify(event_type: str) -> str:
        if event_type in {"ssh"}:
            return "auth"
        if event_type in {"http", "dns", "tls", "flow", "alert"}:
            return "network"
        if event_type in {"fileinfo"}:
            return "endpoint"
        return "network"


# ---------------------------------------------------------------------------
# Generic CEF (used by QRadar, ArcSight, many vendors)
# ---------------------------------------------------------------------------


_CEF_RE = re.compile(r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$")


class CEFAdapter(BaseSIEMAdapter):
    """Parses CEF lines.

    CEF:Version|Vendor|Product|Version|SigID|Name|Severity|key=val key=val
    """

    source_system = "qradar"  # CEF is the QRadar export format

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8", errors="replace")
        if isinstance(payload, list):
            lines = [str(p) for p in payload]
        else:
            lines = [str(payload)]
        out: List[Dict[str, Any]] = []
        for raw in lines:
            for line in raw.splitlines():
                line = line.strip()
                if "CEF:" not in line:
                    continue
                m = _CEF_RE.search(line)
                if not m:
                    continue
                _ver, vendor, product, prodver, sigid, name, sev, ext = m.groups()
                ext_map = self._parse_ext(ext)
                out.append({
                    "source_system": self.source_system,
                    "event_type": self._classify(name, product, ext_map),
                    "severity": normalize_severity(sev),
                    "source_ip": _safe_str(ext_map.get("src") or ext_map.get("sourceAddress")),
                    "destination_ip": _safe_str(ext_map.get("dst") or ext_map.get("destinationAddress")),
                    "user": _safe_str(ext_map.get("suser") or ext_map.get("duser")),
                    "host": _safe_str(ext_map.get("dvchost") or ext_map.get("dvc")),
                    "message": _safe_str(ext_map.get("msg") or name),
                    "timestamp": _safe_str(ext_map.get("rt") or _now_iso()),
                    "raw": {
                        "vendor": vendor, "product": product, "version": prodver,
                        "signature_id": sigid, "name": name, "severity": sev,
                        "extensions": ext_map, "_raw": line,
                    },
                })
        return out

    @staticmethod
    def _parse_ext(ext: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for m in _CEF_EXT_RE.finditer(ext):
            out[m.group(1)] = m.group(2).strip()
        return out

    @staticmethod
    def _classify(name: str, product: str, ext: Dict[str, str]) -> str:
        n = (name or "").lower()
        p = (product or "").lower()
        if "logon" in n or "auth" in n or "login" in n or "sshd" in p:
            return "auth"
        if "firewall" in p or "ids" in p or "ips" in p or "block" in n or "drop" in n:
            return "network"
        if "edr" in p or "endpoint" in p or "process" in n:
            return "endpoint"
        return "application"


# ---------------------------------------------------------------------------
# Syslog (RFC 3164/5424) — generic fallback
# ---------------------------------------------------------------------------


_SYSLOG_PRI_RE = re.compile(r"^<(\d+)>")
_SYSLOG_5424_RE = re.compile(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$")
_SYSLOG_3164_RE = re.compile(r"^(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+([^:]+):\s*(.*)$")
_SYSLOG_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_SYSLOG_USER_RE = re.compile(r"(?:user|for)\s+(\S+)", re.IGNORECASE)
_CEF_EXT_RE = re.compile(r"(\w+)=([^=]+?)(?=\s+\w+=|$)")


class SyslogAdapter(BaseSIEMAdapter):
    """Parses RFC 3164/5424 syslog lines."""

    source_system = "syslog"

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8", errors="replace")
        if isinstance(payload, list):
            lines: List[str] = []
            for p in payload:
                lines.extend(str(p).splitlines())
        else:
            lines = str(payload).splitlines()
        out: List[Dict[str, Any]] = []
        for raw in lines:
            line = raw.strip()
            if not line:
                continue
            sev_level = 6
            pri_m = _SYSLOG_PRI_RE.match(line)
            if pri_m:
                pri = int(pri_m.group(1))
                sev_level = pri & 0x07
                line_body = line[pri_m.end():]
            else:
                line_body = line
            sev_map = {0: "critical", 1: "critical", 2: "critical", 3: "high",
                       4: "high", 5: "medium", 6: "info", 7: "info"}
            sev = sev_map.get(sev_level, "info")
            host = ""
            app = ""
            msg = line_body
            ts = _now_iso()
            m5424 = _SYSLOG_5424_RE.match(line_body)
            if m5424:
                _ver, ts_field, host, app, _proc, _msgid, msg = m5424.groups()
                ts = ts_field if ts_field != "-" else ts
            else:
                m3164 = _SYSLOG_3164_RE.match(line_body)
                if m3164:
                    _ts, host, app, msg = m3164.groups()
            out.append({
                "source_system": self.source_system,
                "event_type": self._classify(app, msg),
                "severity": sev,
                "source_ip": self._extract_ip(msg),
                "destination_ip": "",
                "user": self._extract_user(msg),
                "host": host,
                "message": msg,
                "timestamp": ts,
                "raw": {"pri": sev_level, "host": host, "app": app, "_raw": line},
            })
        return out

    @staticmethod
    def _classify(app: str, msg: str) -> str:
        a = (app or "").lower()
        m = (msg or "").lower()
        if "sshd" in a or "sudo" in a or "login" in m or "authentication" in m:
            return "auth"
        if "kernel" in a or "iptables" in a or "ufw" in a:
            return "network"
        return "application"

    @staticmethod
    def _extract_ip(msg: str) -> str:
        m = _SYSLOG_IP_RE.search(msg or "")
        return m.group(1) if m else ""

    @staticmethod
    def _extract_user(msg: str) -> str:
        m = _SYSLOG_USER_RE.search(msg or "")
        return m.group(1).strip(",;") if m else ""


# ---------------------------------------------------------------------------
# JSON-Lines generic fallback
# ---------------------------------------------------------------------------


class JSONLinesAdapter(BaseSIEMAdapter):
    """Parses generic newline-delimited JSON or JSON array."""

    source_system = "generic"

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8", errors="replace")
        recs: List[Dict[str, Any]] = []
        if isinstance(payload, list):
            recs = [r for r in payload if isinstance(r, dict)]
        elif isinstance(payload, dict):
            recs = [payload]
        elif isinstance(payload, str):
            for line in payload.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        recs.append(obj)
                    elif isinstance(obj, list):
                        recs.extend(o for o in obj if isinstance(o, dict))
                except (json.JSONDecodeError, ValueError):
                    continue
        out: List[Dict[str, Any]] = []
        for rec in recs:
            out.append({
                "source_system": _safe_str(rec.get("source_system") or "generic"),
                "event_type": _safe_str(rec.get("event_type") or "application"),
                "severity": normalize_severity(rec.get("severity") or rec.get("level")),
                "source_ip": _safe_str(rec.get("source_ip") or rec.get("src_ip")),
                "destination_ip": _safe_str(rec.get("destination_ip") or rec.get("dst_ip")),
                "user": _safe_str(rec.get("user") or rec.get("username")),
                "host": _safe_str(rec.get("host") or rec.get("hostname")),
                "message": _safe_str(rec.get("message") or rec.get("msg")),
                "timestamp": _safe_str(rec.get("timestamp") or _now_iso()),
                "raw": rec,
            })
        return out


# ---------------------------------------------------------------------------
# Adapter registry & dispatcher
# ---------------------------------------------------------------------------


_ADAPTERS: Dict[str, BaseSIEMAdapter] = {
    "splunk_hec": SplunkHECAdapter(),
    "splunk": SplunkHECAdapter(),
    "datadog": DatadogAdapter(),
    "sentinel_kql": SentinelKQLAdapter(),
    "sentinel": SentinelKQLAdapter(),
    "elk_bulk": ELKBulkAdapter(),
    "elk": ELKBulkAdapter(),
    "elastic": ELKBulkAdapter(),
    "wazuh_alert": WazuhAdapter(),
    "wazuh": WazuhAdapter(),
    "suricata_eve": SuricataAdapter(),
    "suricata": SuricataAdapter(),
    "cef": CEFAdapter(),
    "qradar": CEFAdapter(),
    "syslog": SyslogAdapter(),
    "json_lines": JSONLinesAdapter(),
    "generic": JSONLinesAdapter(),
}


def list_adapters() -> List[str]:
    """Return canonical adapter names."""
    return sorted({a.source_system for a in _ADAPTERS.values()})


def detect_format(payload: Any) -> str:
    """Best-effort auto-detection. Returns adapter key."""
    if isinstance(payload, dict):
        if "tables" in payload and isinstance(payload.get("tables"), list):
            return "sentinel_kql"
        if "ddsource" in payload or "ddtags" in payload:
            return "datadog"
        if "event" in payload and ("time" in payload or "sourcetype" in payload):
            return "splunk_hec"
        if "rule" in payload and "agent" in payload:
            return "wazuh_alert"
        if "event_type" in payload and ("src_ip" in payload or "dest_ip" in payload):
            return "suricata_eve"
        return "json_lines"
    if isinstance(payload, list) and payload:
        first = payload[0]
        if isinstance(first, dict):
            if "ddsource" in first or "ddtags" in first:
                return "datadog"
            if "event" in first and "time" in first:
                return "splunk_hec"
            if "rule" in first and "agent" in first:
                return "wazuh_alert"
            if "event_type" in first and ("src_ip" in first or "dest_ip" in first):
                return "suricata_eve"
        return "json_lines"
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", errors="replace")
    if isinstance(payload, str):
        if "CEF:" in payload:
            return "cef"
        if payload.lstrip().startswith("<") and ">" in payload[:8]:
            return "syslog"
        # Try one JSON line
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                return "syslog"
            if isinstance(obj, dict):
                if "tables" in obj:
                    return "sentinel_kql"
                if "ddsource" in obj or "ddtags" in obj:
                    return "datadog"
                if "event" in obj and "time" in obj:
                    return "splunk_hec"
                if "rule" in obj and "agent" in obj:
                    return "wazuh_alert"
                if "event_type" in obj and ("src_ip" in obj or "dest_ip" in obj):
                    return "suricata_eve"
                return "json_lines"
            break
    return "json_lines"


def parse(payload: Any, fmt: str = "auto") -> List[Dict[str, Any]]:
    """Parse a payload using the named adapter or auto-detect.

    Args:
        payload: bytes/str/dict/list — raw SIEM input.
        fmt:     adapter key, or "auto" (default).

    Returns:
        List of NormalizedEvent dicts. Empty list on no parsable records.
    """
    if fmt == "auto":
        fmt = detect_format(payload)
    adapter = _ADAPTERS.get(fmt.lower()) or _ADAPTERS["json_lines"]
    try:
        return adapter.parse(payload)
    except Exception:  # noqa: BLE001 — we never want a parse error to crash ingest
        logger.exception("siem_connector.parse failed for fmt=%s", fmt)
        return []


# ---------------------------------------------------------------------------
# Mirror dispatcher: write to all 3 engines
# ---------------------------------------------------------------------------


def mirror_to_engines(
    org_id: str,
    events: List[Dict[str, Any]],
    *,
    siem_engine: Any = None,
    correlation_engine: Any = None,
    findings_engine: Any = None,
    source_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Mirror normalized events to SIEM, correlation, and findings engines.

    Engines are looked up lazily if not provided. Each engine call is wrapped
    in try/except so a single engine failure never blocks the others.

    Returns:
        {"siem_events": int, "correlation_events": int, "findings": int, "errors": [...]}.
    """
    errors: List[str] = []
    siem_count = corr_count = find_count = 0

    if siem_engine is None:
        try:
            from core.siem_integration_engine import SIEMIntegrationEngine
            siem_engine = SIEMIntegrationEngine()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"siem_engine_init: {exc}")
    if correlation_engine is None:
        try:
            from core.security_event_correlation_engine import (
                SecurityEventCorrelationEngine,
            )
            correlation_engine = SecurityEventCorrelationEngine()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"correlation_engine_init: {exc}")
    if findings_engine is None:
        try:
            from core.security_findings_engine import SecurityFindingsEngine
            findings_engine = SecurityFindingsEngine()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"findings_engine_init: {exc}")

    for ev in events:
        # 1) SIEM source events
        if siem_engine is not None:
            try:
                siem_engine.ingest_siem_event(org_id, {
                    "source_id": source_id or f"connector-{ev.get('source_system', 'unknown')}",
                    "event_type": ev.get("event_type", "application"),
                    "severity": ev.get("severity", "info"),
                    "raw_data": ev.get("raw", {}),
                    "parsed_fields": {
                        "source_ip": ev.get("source_ip", ""),
                        "destination_ip": ev.get("destination_ip", ""),
                        "user": ev.get("user", ""),
                        "host": ev.get("host", ""),
                        "message": ev.get("message", ""),
                        "timestamp": ev.get("timestamp", ""),
                        "source_system": ev.get("source_system", ""),
                    },
                })
                siem_count += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"siem_ingest: {exc}")

        # 2) Security event correlation
        if correlation_engine is not None:
            try:
                correlation_engine.ingest_event(org_id, {
                    "source_system": ev.get("source_system", "generic"),
                    "event_type": ev.get("event_type", "application"),
                    "severity": ev.get("severity", "medium")
                                if ev.get("severity") != "info" else "low",
                    "entity_id": ev.get("user") or ev.get("source_ip") or ev.get("host") or "unknown",
                    "entity_type": "user" if ev.get("user") else ("ip" if ev.get("source_ip") else "host"),
                    "raw_data": ev.get("raw", {}),
                    "timestamp": ev.get("timestamp", ""),
                })
                corr_count += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"correlation_ingest: {exc}")

        # 3) SecurityFindings — only for medium+ severity, to avoid swamping
        sev = ev.get("severity", "info")
        if findings_engine is not None and sev in {"medium", "high", "critical"}:
            try:
                # CVSS approximation from severity tier.
                cvss = {"medium": 5.0, "high": 7.5, "critical": 9.5}.get(sev, 0.0)
                findings_engine.record_finding(
                    org_id=org_id,
                    title=(ev.get("message") or f"{ev.get('source_system')} {ev.get('event_type')}")[:200],
                    finding_type=ev.get("event_type", "application"),
                    source_tool=ev.get("source_system", "siem"),
                    severity=sev,
                    cvss_score=cvss,
                    asset_id=ev.get("host") or ev.get("source_ip") or ev.get("user") or "unknown",
                    asset_type="host" if ev.get("host") else "ip",
                    description=ev.get("message", ""),
                    remediation="Investigate via SIEM correlation; see raw event for context.",
                    correlation_key=f"siem|{ev.get('source_system')}|{ev.get('message','')[:80]}",
                )
                find_count += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"findings_record: {exc}")

    return {
        "siem_events": siem_count,
        "correlation_events": corr_count,
        "findings": find_count,
        "errors": errors,
    }


def ingest(
    org_id: str,
    payload: Any,
    fmt: str = "auto",
    *,
    source_id: Optional[str] = None,
    siem_engine: Any = None,
    correlation_engine: Any = None,
    findings_engine: Any = None,
) -> Dict[str, Any]:
    """High-level ingest: parse + mirror.

    Args:
        org_id:  Tenant identifier.
        payload: Raw SIEM payload (bytes/str/dict/list).
        fmt:     Adapter key or "auto".

    Returns:
        Combined result with parsed_count + mirror counts.
    """
    parsed = parse(payload, fmt=fmt)
    if not parsed:
        return {
            "format": fmt if fmt != "auto" else detect_format(payload),
            "parsed_count": 0,
            "siem_events": 0,
            "correlation_events": 0,
            "findings": 0,
            "errors": ["no parsable records"],
        }
    mirror = mirror_to_engines(
        org_id,
        parsed,
        siem_engine=siem_engine,
        correlation_engine=correlation_engine,
        findings_engine=findings_engine,
        source_id=source_id,
    )
    emit_connector_event(
        connector="SIEMConnector",
        org_id=org_id,
        source_kind="siem",
        finding_count=int(mirror.get("findings", 0)),
        extra={
            "parsed_count": len(parsed),
            "siem_events": mirror.get("siem_events", 0),
            "correlation_events": mirror.get("correlation_events", 0),
            "format": fmt if fmt != "auto" else detect_format(payload),
            "source_id": source_id or "",
        },
    )
    return {
        "format": fmt if fmt != "auto" else detect_format(payload),
        "parsed_count": len(parsed),
        **mirror,
    }


# ---------------------------------------------------------------------------
# Real log-file tailer — ingests from real files on disk
# ---------------------------------------------------------------------------


# Per-file byte cursor (in-memory + on-disk for crash recovery).
_TAIL_STATE_FILE_DEFAULT = ".aldeci/siem_tail_cursors.json"


def _load_tail_state(state_path: str) -> Dict[str, int]:
    try:
        from pathlib import Path
        p = Path(state_path)
        if p.exists():
            return json.loads(p.read_text()) or {}
    except (OSError, ValueError):
        pass
    return {}


def _save_tail_state(state_path: str, cursors: Dict[str, int]) -> None:
    try:
        from pathlib import Path
        p = Path(state_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(cursors))
    except OSError as exc:
        logger.debug("siem_connector: tail state write failed: %s", exc)


def tail_log_files(
    org_id: str,
    file_paths: List[str],
    *,
    fmt: str = "auto",
    max_bytes_per_file: int = 1_048_576,  # 1 MiB per file per call
    max_lines_per_file: int = 5000,
    state_path: str = _TAIL_STATE_FILE_DEFAULT,
    siem_engine: Any = None,
    correlation_engine: Any = None,
    findings_engine: Any = None,
) -> Dict[str, Any]:
    """Tail real log files on disk; ingest new bytes since last call.

    Designed for /var/log/system.log, structlog JSONL output, etc.
    Persists per-file byte cursors to ``state_path`` so subsequent calls
    only ingest new content.

    Args:
        org_id:        Tenant identifier.
        file_paths:    List of absolute log file paths to tail.
        fmt:           Adapter key (auto-detect per file).
        max_bytes_per_file: Cap reads per file per call (DoS guard).
        max_lines_per_file: Cap parsed records per file per call.
        state_path:    JSON file storing per-file byte cursors.

    Returns:
        Aggregate dict {files: [...], total_lines, parsed, ingested, errors}.
    """
    from pathlib import Path

    cursors = _load_tail_state(state_path)
    files_report: List[Dict[str, Any]] = []
    aggregate_lines = 0
    aggregate_parsed = 0
    aggregate_ingested = 0
    errors: List[str] = []

    for raw_path in file_paths:
        if not isinstance(raw_path, str) or not raw_path:
            errors.append(f"invalid path: {raw_path!r}")
            continue
        try:
            path = Path(raw_path).resolve()
        except (OSError, ValueError) as exc:
            errors.append(f"path resolve failed {raw_path}: {exc}")
            continue
        if not path.exists() or not path.is_file():
            errors.append(f"missing file: {path}")
            files_report.append(
                {"path": str(path), "exists": False, "lines": 0, "parsed": 0, "ingested": 0}
            )
            continue

        try:
            stat = path.stat()
        except OSError as exc:
            errors.append(f"stat failed {path}: {exc}")
            continue

        cursor = int(cursors.get(str(path), 0))
        # Detect log rotation (file shorter than cursor) — start over.
        if cursor > stat.st_size:
            cursor = 0

        end = min(stat.st_size, cursor + max_bytes_per_file)
        if end <= cursor:
            files_report.append(
                {"path": str(path), "exists": True, "lines": 0, "parsed": 0, "ingested": 0,
                 "cursor": cursor}
            )
            continue

        try:
            with path.open("rb") as fh:
                fh.seek(cursor)
                chunk = fh.read(end - cursor)
        except OSError as exc:
            errors.append(f"read failed {path}: {exc}")
            continue

        text = chunk.decode("utf-8", errors="replace")
        lines = [ln for ln in text.splitlines() if ln.strip()][:max_lines_per_file]
        if not lines:
            cursors[str(path)] = end
            files_report.append(
                {"path": str(path), "exists": True, "lines": 0, "parsed": 0, "ingested": 0,
                 "cursor": end}
            )
            continue

        # Decide adapter per file; structlog/JSON → json_lines, else syslog.
        per_file_fmt = fmt
        if per_file_fmt == "auto":
            sample = lines[0].lstrip()
            if sample.startswith("{"):
                per_file_fmt = "json_lines"
            else:
                per_file_fmt = "syslog"

        # Build payload (newline-joined for parsers that expect a stream).
        payload = "\n".join(lines)
        try:
            parsed = parse(payload, fmt=per_file_fmt)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"parse failed {path}: {exc}")
            parsed = []

        ingested = 0
        if parsed:
            try:
                mirror = mirror_to_engines(
                    org_id,
                    parsed,
                    siem_engine=siem_engine,
                    correlation_engine=correlation_engine,
                    findings_engine=findings_engine,
                    source_id=f"file:{path.name}",
                )
                ingested = mirror.get("siem_events", 0)
                if mirror.get("errors"):
                    errors.extend(
                        f"mirror[{path.name}]: {e}" for e in mirror["errors"][:3]
                    )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"mirror failed {path}: {exc}")

        # Advance cursor to end of read region (only on success — on failure
        # we'd retry next call from the same offset).
        cursors[str(path)] = end

        files_report.append(
            {
                "path": str(path),
                "exists": True,
                "fmt": per_file_fmt,
                "lines": len(lines),
                "parsed": len(parsed),
                "ingested": ingested,
                "cursor": end,
            }
        )
        aggregate_lines += len(lines)
        aggregate_parsed += len(parsed)
        aggregate_ingested += ingested

    _save_tail_state(state_path, cursors)
    emit_connector_event(
        connector="SIEMConnector",
        org_id=org_id,
        source_kind="siem",
        finding_count=aggregate_ingested,
        extra={
            "mode": "tail_log_files",
            "files": len(file_paths),
            "total_lines": aggregate_lines,
            "total_parsed": aggregate_parsed,
        },
    )
    return {
        "org_id": org_id,
        "files": files_report,
        "total_lines": aggregate_lines,
        "total_parsed": aggregate_parsed,
        "total_ingested": aggregate_ingested,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Realistic event generator (15-tenant fixture)
# ---------------------------------------------------------------------------


_AUTH_SAMPLES = [
    "Failed password for {user} from {sip} port {port} ssh2",
    "Failed password for invalid user {user} from {sip} port {port} ssh2",
    "Accepted publickey for {user} from {sip} port {port} ssh2",
    "sudo: {user} : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/{user} ; USER=root",
    "su: FAILED su for root by {user}",
    "PAM: 5 more authentication failures; logname={user} uid=1000",
]

_NGINX_SAMPLES = [
    '{sip} - - [01/Mar/2026:10:15:23 +0000] "GET /admin?id=1\' OR \'1\'=\'1 HTTP/1.1" 403 0 "-" "sqlmap/1.7.2"',
    '{sip} - - [01/Mar/2026:10:15:24 +0000] "GET /../../../../etc/passwd HTTP/1.1" 400 0',
    '{sip} - - [01/Mar/2026:10:15:25 +0000] "POST /login HTTP/1.1" 401 24',
    '{sip} - - [01/Mar/2026:10:15:26 +0000] "GET / HTTP/1.1" 200 612',
    '{sip} - - [01/Mar/2026:10:15:27 +0000] "GET /.git/config HTTP/1.1" 404 162',
    '{sip} - - [01/Mar/2026:10:15:28 +0000] "GET /wp-admin/ HTTP/1.1" 404 162',
]

_WIN_EVENTS = [
    {"event_id": 4625, "msg": "An account failed to log on.", "ev_type": "auth", "sev": "high"},
    {"event_id": 4720, "msg": "A user account was created.", "ev_type": "auth", "sev": "medium"},
    {"event_id": 7045, "msg": "A new service was installed in the system.", "ev_type": "endpoint", "sev": "medium"},
    {"event_id": 4624, "msg": "An account was successfully logged on.", "ev_type": "auth", "sev": "info"},
    {"event_id": 4688, "msg": "A new process has been created.", "ev_type": "endpoint", "sev": "info"},
    {"event_id": 4672, "msg": "Special privileges assigned to new logon.", "ev_type": "auth", "sev": "high"},
]

_K8S_AUDIT = [
    {"verb": "create", "resource": "pods", "user": "system:anonymous"},
    {"verb": "get", "resource": "secrets", "user": "system:serviceaccount:default:default"},
    {"verb": "exec", "resource": "pods/exec", "user": "kubernetes-admin"},
    {"verb": "delete", "resource": "deployments", "user": "ci-bot"},
    {"verb": "patch", "resource": "rolebindings", "user": "kube-admin"},
]

_USERS = ["admin", "alice", "bob", "carol", "deploy", "ci", "root", "guest", "svc_app"]
_HOSTS = ["web-01", "web-02", "db-01", "db-02", "app-01", "ingress-01", "k8s-master", "edge-01"]


def _random_ip(rng) -> str:
    import random as _r  # noqa: F401  (rng is a Random instance)
    return f"{rng.randint(10, 250)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _build_splunk_hec_event(rng, tenant: str) -> Dict[str, Any]:
    user = rng.choice(_USERS)
    sip = _random_ip(rng)
    port = rng.randint(30000, 65000)
    msg = rng.choice(_AUTH_SAMPLES).format(user=user, sip=sip, port=port)
    return {
        "event": {
            "_raw": msg, "src": sip, "src_user": user,
            "host": rng.choice(_HOSTS), "severity": "high" if "Failed" in msg else "info",
        },
        "time": datetime.now(timezone.utc).timestamp(),
        "host": rng.choice(_HOSTS),
        "source": "/var/log/auth.log",
        "sourcetype": "linux_secure",
        "index": f"sec_{tenant}",
        "fields": {"tenant": tenant},
    }


def _build_datadog_event(rng, tenant: str) -> Dict[str, Any]:
    sip = _random_ip(rng)
    msg = rng.choice(_NGINX_SAMPLES).format(sip=sip)
    is_attack = "sqlmap" in msg or "../" in msg
    return {
        "ddsource": "nginx",
        "ddtags": f"env:prod,tenant:{tenant},service:web",
        "hostname": rng.choice(_HOSTS),
        "service": "web",
        "message": msg,
        "status": "error" if is_attack else "info",
        "timestamp": _now_iso(),
        "network.client.ip": sip,
    }


def _build_sentinel_event(rng, tenant: str) -> Dict[str, Any]:
    win = rng.choice(_WIN_EVENTS)
    return {
        "tables": [{
            "name": "SecurityEvent",
            "columns": [
                {"name": "TimeGenerated", "type": "datetime"},
                {"name": "EventID", "type": "int"},
                {"name": "Computer", "type": "string"},
                {"name": "AccountName", "type": "string"},
                {"name": "IPAddress", "type": "string"},
                {"name": "Activity", "type": "string"},
                {"name": "Severity", "type": "string"},
                {"name": "Tenant", "type": "string"},
            ],
            "rows": [[
                _now_iso(), win["event_id"], rng.choice(_HOSTS),
                rng.choice(_USERS), _random_ip(rng), win["msg"],
                win["sev"], tenant,
            ]],
        }],
    }


def _build_elk_event(rng, tenant: str) -> Dict[str, Any]:
    sip = _random_ip(rng)
    return {
        "@timestamp": _now_iso(),
        "host": {"name": rng.choice(_HOSTS)},
        "user": {"name": rng.choice(_USERS)},
        "source": {"ip": sip},
        "destination": {"ip": _random_ip(rng)},
        "event": {
            "category": rng.choice(["network", "authentication", "process"]),
            "action": rng.choice(["connection", "login", "exec"]),
            "severity": rng.choice([3, 5, 7, 9]),
        },
        "message": "Elastic SIEM event",
        "tenant": tenant,
    }


def _build_wazuh_event(rng, tenant: str) -> Dict[str, Any]:
    level = rng.choice([3, 5, 7, 10, 12, 15])
    return {
        "timestamp": _now_iso(),
        "rule": {
            "level": level,
            "id": str(rng.randint(5500, 5800)),
            "description": rng.choice([
                "sshd: brute force trying to get access to the system.",
                "PAM: Login session opened.",
                "Possible kernel level rootkit.",
                "Audit: Command executed.",
            ]),
            "groups": rng.choice([
                ["authentication_failures", "ssh", "authentication_failed"],
                ["pam", "authentication_success"],
                ["rootcheck"],
                ["audit", "audit_command"],
            ]),
        },
        "agent": {"id": f"00{rng.randint(1, 9)}", "name": rng.choice(_HOSTS), "ip": _random_ip(rng)},
        "data": {"srcip": _random_ip(rng), "dstuser": rng.choice(_USERS)},
        "full_log": "Mar  1 10:15:23 host sshd[1234]: Failed password from {}".format(_random_ip(rng)),
        "manager": {"name": "wazuh-manager"},
        "tenant": tenant,
    }


def _build_cef_event(rng, tenant: str) -> str:
    sip = _random_ip(rng)
    dip = _random_ip(rng)
    sev = rng.choice([3, 5, 7, 9])
    sigid = rng.randint(100, 999)
    return (
        f"CEF:0|IBM|QRadar|7.5|{sigid}|"
        f"Suspicious Outbound Connection|{sev}|"
        f"src={sip} dst={dip} suser={rng.choice(_USERS)} "
        f"dvchost={rng.choice(_HOSTS)} msg=Connection blocked by policy "
        f"rt={_now_iso()} tenant={tenant}"
    )


def _build_syslog_event(rng, tenant: str) -> str:
    sip = _random_ip(rng)
    user = rng.choice(_USERS)
    pri = rng.choice([34, 38, 86, 174])  # auth.* priorities
    return (
        f"<{pri}>1 {_now_iso()} {rng.choice(_HOSTS)} sshd 1234 - - "
        f"Failed password for {user} from {sip} port {rng.randint(30000, 65000)} ssh2 [tenant={tenant}]"
    )


def _build_suricata_event(rng, tenant: str) -> Dict[str, Any]:
    return {
        "timestamp": _now_iso(),
        "event_type": "alert",
        "src_ip": _random_ip(rng),
        "dest_ip": _random_ip(rng),
        "src_port": rng.randint(30000, 65000),
        "dest_port": rng.choice([22, 80, 443, 3306, 8080]),
        "proto": "TCP",
        "alert": {
            "signature": rng.choice([
                "ET POLICY SSH brute force attempt",
                "ET MALWARE Possible Cobalt Strike Beacon",
                "ET SCAN Nmap TCP scan",
                "ET WEB_SPECIFIC_APPS SQL Injection attempt",
            ]),
            "severity": rng.choice([1, 2, 3]),
            "category": "Attempted Information Leak",
        },
        "tenant": tenant,
    }


def _build_k8s_audit(rng, tenant: str) -> Dict[str, Any]:
    audit = rng.choice(_K8S_AUDIT)
    return {
        "ddsource": "kubernetes",
        "ddtags": f"env:prod,tenant:{tenant},k8s.namespace:default",
        "hostname": "k8s-audit",
        "service": "k8s",
        "message": f"k8s.audit verb={audit['verb']} resource={audit['resource']} user={audit['user']}",
        "status": "warning" if audit["user"] == "system:anonymous" else "info",
        "timestamp": _now_iso(),
        "user": audit["user"],
        "verb": audit["verb"],
        "resource": audit["resource"],
    }


_GENERATORS: List[Tuple[str, Any]] = [
    ("splunk_hec", _build_splunk_hec_event),
    ("datadog", _build_datadog_event),
    ("sentinel_kql", _build_sentinel_event),
    ("elk_bulk", _build_elk_event),
    ("wazuh_alert", _build_wazuh_event),
    ("cef", _build_cef_event),
    ("syslog", _build_syslog_event),
    ("suricata_eve", _build_suricata_event),
    ("datadog", _build_k8s_audit),  # k8s audit shipped via Datadog source
]


def generate_events(
    tenants: int = 15,
    events_per_tenant: int = 14,
    seed: int = 1337,
) -> List[Tuple[str, str, Any]]:
    """Generate (tenant_id, format, payload) tuples across N tenants.

    Args:
        tenants: Number of tenants (default 15).
        events_per_tenant: Events per tenant in the 10-20 range (default 14).
        seed: Deterministic RNG seed.

    Returns:
        List of (tenant_id, format, payload) tuples. Total = tenants * events_per_tenant.
    """
    import random
    rng = random.Random(seed)
    out: List[Tuple[str, str, Any]] = []
    for t in range(1, tenants + 1):
        tenant = f"tenant-{t:02d}"
        for _ in range(events_per_tenant):
            fmt, builder = rng.choice(_GENERATORS)
            payload = builder(rng, tenant)
            out.append((tenant, fmt, payload))
    return out


def generate_and_ingest(
    tenants: int = 15,
    events_per_tenant: int = 14,
    seed: int = 1337,
    *,
    siem_engine: Any = None,
    correlation_engine: Any = None,
    findings_engine: Any = None,
) -> Dict[str, Any]:
    """Generate fixture events and run them through the ingest pipeline.

    Returns:
        Summary dict with per-tenant + per-format counts and totals.
    """
    triples = generate_events(tenants=tenants, events_per_tenant=events_per_tenant, seed=seed)
    by_tenant: Dict[str, Dict[str, int]] = {}
    by_format: Dict[str, int] = {}
    totals = {"parsed": 0, "siem_events": 0, "correlation_events": 0, "findings": 0, "errors": 0}
    for tenant, fmt, payload in triples:
        result = ingest(
            tenant, payload, fmt=fmt,
            source_id=f"connector-{fmt}",
            siem_engine=siem_engine,
            correlation_engine=correlation_engine,
            findings_engine=findings_engine,
        )
        by_format[fmt] = by_format.get(fmt, 0) + result.get("parsed_count", 0)
        bucket = by_tenant.setdefault(tenant, {"parsed": 0, "findings": 0})
        bucket["parsed"] += result.get("parsed_count", 0)
        bucket["findings"] += result.get("findings", 0)
        totals["parsed"] += result.get("parsed_count", 0)
        totals["siem_events"] += result.get("siem_events", 0)
        totals["correlation_events"] += result.get("correlation_events", 0)
        totals["findings"] += result.get("findings", 0)
        totals["errors"] += len(result.get("errors", []))
    return {
        "tenants": tenants,
        "events_per_tenant": events_per_tenant,
        "total_inputs": len(triples),
        "totals": totals,
        "by_format": by_format,
        "by_tenant": by_tenant,
    }
