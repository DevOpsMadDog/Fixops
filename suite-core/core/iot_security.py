"""IoT/OT Security Scanner — ALDECI.

Provides comprehensive security scanning for IoT and OT (Operational Technology)
devices including:
- Device inventory (type, manufacturer, firmware, network segment, protocol)
- Firmware analysis (CVE lookup, end-of-life detection, update availability)
- Protocol security (insecure protocols: Telnet, HTTP, MQTT without TLS, default SNMP)
- Network segmentation verification (IoT isolation from corporate network)
- Default credential detection (known default username/password pairs)
- Communication pattern analysis (baseline, C2 beaconing, data exfiltration)
- Compliance mapping (NIST IoT, IEC 62443 OT, FDA medical devices)

SQLite-backed, thread-safe, multi-tenant (per org_id).

Usage:
    from core.iot_security import IoTSecurityEngine, get_iot_engine
    engine = get_iot_engine()
    device = engine.register_device(device_req)
    findings = engine.scan_device(device.id)
"""

from __future__ import annotations

import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

_DEFAULT_DB = os.getenv("FIXOPS_IOT_DB", ".fixops_data/iot_security.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DeviceType(str, Enum):
    CAMERA = "camera"
    THERMOSTAT = "thermostat"
    ROUTER = "router"
    SWITCH = "switch"
    PLC = "plc"
    SCADA = "scada"
    HMI = "hmi"
    SENSOR = "sensor"
    ACTUATOR = "actuator"
    MEDICAL = "medical"
    PRINTER = "printer"
    NVR = "nvr"
    DVR = "dvr"
    SMART_METER = "smart_meter"
    INDUSTRIAL_GATEWAY = "industrial_gateway"
    OTHER = "other"


class DeviceProtocol(str, Enum):
    MQTT = "mqtt"
    MQTTS = "mqtts"
    COAP = "coap"
    COAPS = "coaps"
    MODBUS = "modbus"
    DNPV3 = "dnpv3"
    PROFINET = "profinet"
    BACNET = "bacnet"
    OPCUA = "opcua"
    OPCDA = "opcda"
    HTTP = "http"
    HTTPS = "https"
    TELNET = "telnet"
    SSH = "ssh"
    SNMP = "snmp"
    SNMPV3 = "snmpv3"
    FTP = "ftp"
    TFTP = "tftp"
    OTHER = "other"


class NetworkSegment(str, Enum):
    CORPORATE = "corporate"
    IOT_VLAN = "iot_vlan"
    OT_NETWORK = "ot_network"
    DMZ = "dmz"
    GUEST = "guest"
    ISOLATED = "isolated"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceFramework(str, Enum):
    NIST_IOT = "nist_iot"
    IEC_62443 = "iec_62443"
    FDA_MEDICAL = "fda_medical"
    NERC_CIP = "nerc_cip"
    GDPR = "gdpr"


class FindingCategory(str, Enum):
    FIRMWARE = "firmware"
    PROTOCOL = "protocol"
    CREDENTIALS = "credentials"
    SEGMENTATION = "segmentation"
    COMMUNICATION = "communication"
    COMPLIANCE = "compliance"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class IoTDevice(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    device_type: DeviceType
    manufacturer: str
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    ip_address: str
    mac_address: Optional[str] = None
    network_segment: NetworkSegment = NetworkSegment.UNKNOWN
    vlan_id: Optional[int] = None
    protocols: List[DeviceProtocol] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    location: Optional[str] = None
    org_id: str = "default"
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: Optional[datetime] = None
    risk_score: float = 0.0


class FirmwareFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    manufacturer: str
    firmware_version: str
    cves: List[str] = Field(default_factory=list)
    is_end_of_life: bool = False
    update_available: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.INFO
    details: str = ""
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ProtocolFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    protocol: DeviceProtocol
    port: Optional[int] = None
    is_insecure: bool = False
    reason: str = ""
    recommendation: str = ""
    risk_level: RiskLevel = RiskLevel.INFO
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SegmentationFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    device_segment: NetworkSegment
    expected_segment: NetworkSegment
    is_violation: bool = False
    risk_level: RiskLevel = RiskLevel.INFO
    details: str = ""
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CredentialFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    manufacturer: str
    username: str
    credential_type: str = "password"
    is_default: bool = False
    risk_level: RiskLevel = RiskLevel.INFO
    recommendation: str = ""
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CommunicationPattern(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    remote_ip: str
    remote_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_received: int = 0
    connection_count: int = 1
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str = "default"
    is_baseline: bool = False
    anomaly_flags: List[str] = Field(default_factory=list)


class CommunicationAnomaly(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    anomaly_type: str  # c2_beaconing | data_exfiltration | port_scan | unusual_destination
    remote_ip: str
    remote_port: int
    confidence: float = 0.0  # 0.0-1.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    evidence: Dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ComplianceResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    framework: ComplianceFramework
    control_id: str
    control_name: str
    status: str  # pass | fail | warning | not_applicable
    details: str = ""
    remediation: str = ""
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DeviceScanResult(BaseModel):
    device_id: str
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    firmware_findings: List[FirmwareFinding] = Field(default_factory=list)
    protocol_findings: List[ProtocolFinding] = Field(default_factory=list)
    segmentation_findings: List[SegmentationFinding] = Field(default_factory=list)
    credential_findings: List[CredentialFinding] = Field(default_factory=list)
    communication_anomalies: List[CommunicationAnomaly] = Field(default_factory=list)
    compliance_results: List[ComplianceResult] = Field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.INFO
    risk_score: float = 0.0
    summary: str = ""


class IoTSummary(BaseModel):
    org_id: str
    total_devices: int
    devices_by_type: Dict[str, int]
    devices_by_segment: Dict[str, int]
    devices_by_risk: Dict[str, int]
    critical_findings: int
    high_findings: int
    segmentation_violations: int
    default_credential_devices: int
    eol_firmware_devices: int
    insecure_protocol_devices: int
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Known vulnerability / risk databases (embedded, no external deps)
# ---------------------------------------------------------------------------

# Known CVEs per manufacturer+firmware pattern (manufacturer -> version_prefix -> [CVEs])
_FIRMWARE_CVE_DB: Dict[str, Dict[str, List[str]]] = {
    "hikvision": {
        "5.5": ["CVE-2017-7921", "CVE-2021-36260"],
        "5.4": ["CVE-2017-7921", "CVE-2014-4878"],
        "5.3": ["CVE-2014-4878", "CVE-2014-4879"],
    },
    "dahua": {
        "2.6": ["CVE-2017-6341", "CVE-2021-33044"],
        "2.5": ["CVE-2017-6341"],
    },
    "axis": {
        "5.5": ["CVE-2018-10661", "CVE-2018-10662"],
    },
    "dlink": {
        "1.0": ["CVE-2019-16920", "CVE-2020-25078"],
        "1.1": ["CVE-2020-25078"],
    },
    "netgear": {
        "1.0": ["CVE-2017-5521", "CVE-2019-20760"],
    },
    "siemens": {
        "4.0": ["CVE-2019-13945", "CVE-2020-15782"],
        "3.0": ["CVE-2019-13945"],
    },
    "schneider": {
        "2.0": ["CVE-2018-7789", "CVE-2019-6857"],
    },
    "rockwell": {
        "20.0": ["CVE-2020-6998", "CVE-2020-12038"],
    },
    "philips": {
        "1.0": ["CVE-2019-11687", "CVE-2020-14477"],  # medical
    },
    "ge_healthcare": {
        "1.0": ["CVE-2020-6961", "CVE-2020-6962"],  # medical
    },
}

# End-of-life firmware versions per manufacturer
_EOL_FIRMWARE: Dict[str, List[str]] = {
    "hikvision": ["5.3.0", "5.3.1", "5.4.0", "5.4.1"],
    "dahua": ["2.4.0", "2.5.0"],
    "axis": ["5.4.0", "5.5.0"],
    "dlink": ["1.0.0", "1.0.1"],
    "netgear": ["1.0.0"],
    "siemens": ["3.0.0"],
    "schneider": ["1.0.0", "1.1.0"],
}

# Available firmware updates per manufacturer (current EOL -> latest stable)
_FIRMWARE_UPDATES: Dict[str, str] = {
    "hikvision": "5.7.2",
    "dahua": "2.8.1",
    "axis": "10.12.0",
    "dlink": "1.5.0",
    "netgear": "1.4.2",
    "siemens": "4.5.1",
    "schneider": "3.1.0",
    "rockwell": "22.1.0",
    "philips": "2.3.0",
    "ge_healthcare": "2.1.0",
}

# Default credentials per manufacturer (username, password)
_DEFAULT_CREDENTIALS: Dict[str, List[Tuple[str, str]]] = {
    "hikvision": [("admin", "12345"), ("admin", "admin"), ("admin", "")],
    "dahua": [("admin", "admin"), ("admin", ""), ("888888", "888888")],
    "axis": [("root", "pass"), ("root", ""), ("admin", "admin")],
    "dlink": [("admin", ""), ("admin", "admin"), ("user", "user")],
    "netgear": [("admin", "password"), ("admin", "1234")],
    "cisco": [("cisco", "cisco"), ("admin", "admin"), ("enable", "")],
    "ubiquiti": [("ubnt", "ubnt"), ("admin", "admin")],
    "siemens": [("admin", "admin"), ("user", "user"), ("guest", "guest")],
    "schneider": [("USER", "USER"), ("ADMIN", "ADMIN")],
    "rockwell": [("guest", "guest"), ("admin", "admin")],
    "ge_healthcare": [("admin", "admin"), ("service", "service")],
    "philips": [("admin", "admin"), ("user", "user")],
}

# Insecure protocols and their risks
_INSECURE_PROTOCOLS: Dict[DeviceProtocol, Dict[str, str]] = {
    DeviceProtocol.TELNET: {
        "reason": "Telnet transmits credentials and data in plaintext",
        "recommendation": "Disable Telnet; use SSH for remote management",
        "risk": RiskLevel.CRITICAL,
    },
    DeviceProtocol.HTTP: {
        "reason": "HTTP transmits data without encryption",
        "recommendation": "Enable HTTPS with valid TLS certificate",
        "risk": RiskLevel.HIGH,
    },
    DeviceProtocol.MQTT: {
        "reason": "MQTT without TLS exposes telemetry data in plaintext",
        "recommendation": "Upgrade to MQTTS (MQTT over TLS on port 8883)",
        "risk": RiskLevel.HIGH,
    },
    DeviceProtocol.FTP: {
        "reason": "FTP transmits credentials and files in plaintext",
        "recommendation": "Disable FTP; use SFTP or FTPS",
        "risk": RiskLevel.HIGH,
    },
    DeviceProtocol.TFTP: {
        "reason": "TFTP has no authentication mechanism",
        "recommendation": "Disable TFTP; use authenticated file transfer",
        "risk": RiskLevel.HIGH,
    },
    DeviceProtocol.SNMP: {
        "reason": "SNMPv1/v2 uses community strings instead of strong auth",
        "recommendation": "Upgrade to SNMPv3 with authentication and encryption",
        "risk": RiskLevel.MEDIUM,
    },
    DeviceProtocol.COAP: {
        "reason": "CoAP without DTLS lacks encryption",
        "recommendation": "Use CoAPS (CoAP over DTLS)",
        "risk": RiskLevel.MEDIUM,
    },
}

# Compliance controls per framework
_COMPLIANCE_CONTROLS: Dict[ComplianceFramework, List[Dict[str, str]]] = {
    ComplianceFramework.NIST_IOT: [
        {"id": "NIST-IOT-1.1", "name": "Device Identification", "check": "has_unique_id"},
        {"id": "NIST-IOT-1.2", "name": "Device Configuration", "check": "no_default_credentials"},
        {"id": "NIST-IOT-2.1", "name": "Software Updates", "check": "firmware_current"},
        {"id": "NIST-IOT-3.1", "name": "Cybersecurity Awareness", "check": "secure_protocols"},
        {"id": "NIST-IOT-4.1", "name": "Device Security Monitoring", "check": "network_segmented"},
        {"id": "NIST-IOT-5.1", "name": "Incident Detection", "check": "no_c2_beaconing"},
    ],
    ComplianceFramework.IEC_62443: [
        {"id": "IEC-62443-SR-1.1", "name": "Human User Identification and Authentication", "check": "no_default_credentials"},
        {"id": "IEC-62443-SR-1.2", "name": "Software Process and Device Identification", "check": "has_unique_id"},
        {"id": "IEC-62443-SR-3.1", "name": "Communications Integrity", "check": "secure_protocols"},
        {"id": "IEC-62443-SR-3.3", "name": "Security Functionality Verification", "check": "firmware_current"},
        {"id": "IEC-62443-SR-5.1", "name": "Network Segmentation", "check": "network_segmented"},
        {"id": "IEC-62443-SR-5.2", "name": "Zone Boundary Protection", "check": "proper_vlan"},
    ],
    ComplianceFramework.FDA_MEDICAL: [
        {"id": "FDA-CYBER-1", "name": "Medical Device Cybersecurity", "check": "no_default_credentials"},
        {"id": "FDA-CYBER-2", "name": "Verified Firmware", "check": "firmware_current"},
        {"id": "FDA-CYBER-3", "name": "Secure Communications", "check": "secure_protocols"},
        {"id": "FDA-CYBER-4", "name": "Network Isolation", "check": "network_segmented"},
        {"id": "FDA-CYBER-5", "name": "Anomaly Detection", "check": "no_c2_beaconing"},
        {"id": "FDA-CYBER-6", "name": "Patch Management", "check": "firmware_current"},
    ],
}

# ---------------------------------------------------------------------------
# Risk scoring weights
# ---------------------------------------------------------------------------
_RISK_WEIGHTS = {
    "firmware_critical_cve": 30.0,
    "firmware_eol": 15.0,
    "insecure_protocol_critical": 25.0,
    "insecure_protocol_high": 15.0,
    "default_credentials": 35.0,
    "segmentation_violation": 20.0,
    "c2_beaconing": 40.0,
    "data_exfiltration": 35.0,
}


# ---------------------------------------------------------------------------
# IoTSecurityEngine
# ---------------------------------------------------------------------------

class IoTSecurityEngine:
    """IoT/OT Security Scanner engine.

    Thread-safe SQLite-backed engine for full lifecycle IoT/OT device security.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()
        logger.info("IoTSecurityEngine initialised", db=db_path)

    # ------------------------------------------------------------------
    # DB initialisation
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    last_seen TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_devices_org ON devices(org_id);

                CREATE TABLE IF NOT EXISTS firmware_findings (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    detected_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_fw_device ON firmware_findings(device_id);

                CREATE TABLE IF NOT EXISTS protocol_findings (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    detected_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_proto_device ON protocol_findings(device_id);

                CREATE TABLE IF NOT EXISTS segmentation_findings (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    detected_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_seg_device ON segmentation_findings(device_id);

                CREATE TABLE IF NOT EXISTS credential_findings (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    detected_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cred_device ON credential_findings(device_id);

                CREATE TABLE IF NOT EXISTS communication_patterns (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_comm_device ON communication_patterns(device_id);

                CREATE TABLE IF NOT EXISTS communication_anomalies (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    detected_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_anomaly_device ON communication_anomalies(device_id);

                CREATE TABLE IF NOT EXISTS compliance_results (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    data TEXT NOT NULL,
                    assessed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_comp_device ON compliance_results(device_id);
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Device inventory
    # ------------------------------------------------------------------

    def register_device(self, device: IoTDevice) -> IoTDevice:
        """Register a new IoT/OT device in the inventory."""
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO devices (id, org_id, data, registered_at, last_seen) VALUES (?,?,?,?,?)",
                (
                    device.id,
                    device.org_id,
                    device.model_dump_json(),
                    device.registered_at.isoformat(),
                    device.last_seen.isoformat() if device.last_seen else None,
                ),
            )
        logger.info("device_registered", device_id=device.id, name=device.name, org=device.org_id)
        return device

    def get_device(self, device_id: str) -> Optional[IoTDevice]:
        """Retrieve a device by ID."""
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM devices WHERE id=?", (device_id,)).fetchone()
        if row is None:
            return None
        return IoTDevice.model_validate_json(row["data"])

    def list_devices(self, org_id: str = "default", device_type: Optional[DeviceType] = None,
                     network_segment: Optional[NetworkSegment] = None) -> List[IoTDevice]:
        """List all devices for an org with optional filters."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM devices WHERE org_id=? ORDER BY registered_at DESC",
                (org_id,),
            ).fetchall()
        devices = [IoTDevice.model_validate_json(r["data"]) for r in rows]
        if device_type:
            devices = [d for d in devices if d.device_type == device_type]
        if network_segment:
            devices = [d for d in devices if d.network_segment == network_segment]
        return devices

    def update_device_last_seen(self, device_id: str) -> None:
        """Update last-seen timestamp for a device."""
        now = datetime.now(timezone.utc)
        device = self.get_device(device_id)
        if device is None:
            return
        device.last_seen = now
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE devices SET last_seen=?, data=? WHERE id=?",
                (now.isoformat(), device.model_dump_json(), device_id),
            )

    # ------------------------------------------------------------------
    # Firmware analysis
    # ------------------------------------------------------------------

    def analyse_firmware(self, device: IoTDevice) -> FirmwareFinding:
        """Analyse firmware version for CVEs and EOL status."""
        manufacturer = device.manufacturer.lower()
        firmware = device.firmware_version or ""

        cves: List[str] = []
        is_eol = False
        update_available: Optional[str] = None
        risk_level = RiskLevel.INFO

        # CVE lookup
        if manufacturer in _FIRMWARE_CVE_DB:
            for prefix, cve_list in _FIRMWARE_CVE_DB[manufacturer].items():
                if firmware.startswith(prefix):
                    cves.extend(cve_list)

        # EOL check
        if manufacturer in _EOL_FIRMWARE:
            if firmware in _EOL_FIRMWARE[manufacturer]:
                is_eol = True

        # Update availability
        if manufacturer in _FIRMWARE_UPDATES:
            latest = _FIRMWARE_UPDATES[manufacturer]
            if firmware != latest:
                update_available = latest

        # Risk level
        if cves and is_eol:
            risk_level = RiskLevel.CRITICAL
        elif cves:
            risk_level = RiskLevel.HIGH
        elif is_eol:
            risk_level = RiskLevel.MEDIUM
        elif update_available:
            risk_level = RiskLevel.LOW

        details_parts = []
        if cves:
            details_parts.append(f"Found {len(cves)} CVEs: {', '.join(cves)}")
        if is_eol:
            details_parts.append("Firmware version is end-of-life")
        if update_available:
            details_parts.append(f"Update available: {update_available}")
        if not details_parts:
            details_parts.append("Firmware appears current, no known CVEs")

        finding = FirmwareFinding(
            device_id=device.id,
            manufacturer=device.manufacturer,
            firmware_version=firmware,
            cves=list(set(cves)),
            is_end_of_life=is_eol,
            update_available=update_available,
            risk_level=risk_level,
            details=" | ".join(details_parts),
        )

        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO firmware_findings (id, device_id, data, detected_at) VALUES (?,?,?,?)",
                (finding.id, device.id, finding.model_dump_json(), finding.detected_at.isoformat()),
            )

        logger.info("firmware_analysed", device_id=device.id, cves=len(cves), eol=is_eol)
        return finding

    def get_firmware_findings(self, device_id: str) -> List[FirmwareFinding]:
        """Get all firmware findings for a device."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM firmware_findings WHERE device_id=? ORDER BY detected_at DESC",
                (device_id,),
            ).fetchall()
        return [FirmwareFinding.model_validate_json(r["data"]) for r in rows]

    # ------------------------------------------------------------------
    # Protocol security
    # ------------------------------------------------------------------

    def check_protocols(self, device: IoTDevice) -> List[ProtocolFinding]:
        """Check device protocols for insecure configurations."""
        findings: List[ProtocolFinding] = []

        for protocol in device.protocols:
            if protocol in _INSECURE_PROTOCOLS:
                info = _INSECURE_PROTOCOLS[protocol]
                # SNMP: check if using default community strings
                finding = ProtocolFinding(
                    device_id=device.id,
                    protocol=protocol,
                    is_insecure=True,
                    reason=info["reason"],
                    recommendation=info["recommendation"],
                    risk_level=RiskLevel(info["risk"]),
                )
                findings.append(finding)

        # Check open ports for known-bad services
        insecure_ports = {23: DeviceProtocol.TELNET, 21: DeviceProtocol.FTP, 69: DeviceProtocol.TFTP,
                          80: DeviceProtocol.HTTP, 1883: DeviceProtocol.MQTT}
        declared_protocols = {p for p in device.protocols}

        for port in device.open_ports:
            if port in insecure_ports:
                implied_proto = insecure_ports[port]
                if implied_proto not in declared_protocols and implied_proto in _INSECURE_PROTOCOLS:
                    info = _INSECURE_PROTOCOLS[implied_proto]
                    finding = ProtocolFinding(
                        device_id=device.id,
                        protocol=implied_proto,
                        port=port,
                        is_insecure=True,
                        reason=f"Port {port} open — {info['reason']}",
                        recommendation=info["recommendation"],
                        risk_level=RiskLevel(info["risk"]),
                    )
                    findings.append(finding)

        with self._lock, self._conn() as conn:
            for f in findings:
                conn.execute(
                    "INSERT INTO protocol_findings (id, device_id, data, detected_at) VALUES (?,?,?,?)",
                    (f.id, device.id, f.model_dump_json(), f.detected_at.isoformat()),
                )

        logger.info("protocols_checked", device_id=device.id, insecure_count=len(findings))
        return findings

    def get_protocol_findings(self, device_id: str) -> List[ProtocolFinding]:
        """Get all protocol findings for a device."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM protocol_findings WHERE device_id=? ORDER BY detected_at DESC",
                (device_id,),
            ).fetchall()
        return [ProtocolFinding.model_validate_json(r["data"]) for r in rows]

    # ------------------------------------------------------------------
    # Network segmentation
    # ------------------------------------------------------------------

    def verify_segmentation(self, device: IoTDevice) -> SegmentationFinding:
        """Verify network segmentation for an IoT/OT device."""
        # Devices that should be isolated
        ot_types = {DeviceType.PLC, DeviceType.SCADA, DeviceType.HMI, DeviceType.ACTUATOR}
        iot_types = {DeviceType.CAMERA, DeviceType.THERMOSTAT, DeviceType.SENSOR,
                     DeviceType.SMART_METER, DeviceType.NVR, DeviceType.DVR, DeviceType.PRINTER}
        medical_types = {DeviceType.MEDICAL}

        is_violation = False
        risk_level = RiskLevel.INFO
        details = ""

        if device.device_type in ot_types:
            expected = NetworkSegment.OT_NETWORK
            if device.network_segment == NetworkSegment.CORPORATE:
                is_violation = True
                risk_level = RiskLevel.CRITICAL
                details = (
                    f"OT device ({device.device_type.value}) is on corporate network. "
                    "OT devices must be isolated in a dedicated OT network segment."
                )
            elif device.network_segment not in {NetworkSegment.OT_NETWORK, NetworkSegment.ISOLATED}:
                is_violation = True
                risk_level = RiskLevel.HIGH
                details = (
                    f"OT device is on {device.network_segment.value} instead of OT network."
                )
        elif device.device_type in medical_types:
            expected = NetworkSegment.ISOLATED
            if device.network_segment == NetworkSegment.CORPORATE:
                is_violation = True
                risk_level = RiskLevel.CRITICAL
                details = (
                    "Medical device is on corporate network. "
                    "Medical devices require isolated network segments per FDA guidelines."
                )
            elif device.network_segment not in {NetworkSegment.ISOLATED, NetworkSegment.IOT_VLAN}:
                is_violation = True
                risk_level = RiskLevel.HIGH
                details = f"Medical device is on {device.network_segment.value} instead of isolated segment."
        elif device.device_type in iot_types:
            expected = NetworkSegment.IOT_VLAN
            if device.network_segment == NetworkSegment.CORPORATE:
                is_violation = True
                risk_level = RiskLevel.HIGH
                details = (
                    f"IoT device ({device.device_type.value}) is on corporate network. "
                    "IoT devices should be on a dedicated IoT VLAN."
                )
            elif device.network_segment == NetworkSegment.UNKNOWN:
                is_violation = True
                risk_level = RiskLevel.MEDIUM
                details = "IoT device has unknown network segment — segmentation cannot be verified."
        else:
            expected = NetworkSegment.IOT_VLAN

        if not details:
            details = f"Device correctly placed in {device.network_segment.value} segment."

        finding = SegmentationFinding(
            device_id=device.id,
            device_segment=device.network_segment,
            expected_segment=expected,
            is_violation=is_violation,
            risk_level=risk_level,
            details=details,
        )

        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO segmentation_findings (id, device_id, data, detected_at) VALUES (?,?,?,?)",
                (finding.id, device.id, finding.model_dump_json(), finding.detected_at.isoformat()),
            )

        logger.info("segmentation_verified", device_id=device.id, violation=is_violation)
        return finding

    def get_segmentation_findings(self, device_id: str) -> List[SegmentationFinding]:
        """Get all segmentation findings for a device."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM segmentation_findings WHERE device_id=? ORDER BY detected_at DESC",
                (device_id,),
            ).fetchall()
        return [SegmentationFinding.model_validate_json(r["data"]) for r in rows]

    # ------------------------------------------------------------------
    # Default credential detection
    # ------------------------------------------------------------------

    def check_default_credentials(self, device: IoTDevice,
                                  supplied_credentials: Optional[List[Tuple[str, str]]] = None) -> List[CredentialFinding]:
        """Check for default credentials per manufacturer."""
        findings: List[CredentialFinding] = []
        manufacturer = device.manufacturer.lower()

        # Use supplied credentials if provided, else check against known defaults
        creds_to_check = supplied_credentials or []
        known_defaults = _DEFAULT_CREDENTIALS.get(manufacturer, [])

        if not creds_to_check and not known_defaults:
            return findings

        # If no credentials supplied, flag that defaults exist and should be checked
        if not creds_to_check and known_defaults:
            for username, _ in known_defaults:
                finding = CredentialFinding(
                    device_id=device.id,
                    manufacturer=device.manufacturer,
                    username=username,
                    credential_type="password",
                    is_default=True,
                    risk_level=RiskLevel.CRITICAL,
                    recommendation=(
                        f"Change default credentials for {device.manufacturer} devices. "
                        f"Username '{username}' has a known default password."
                    ),
                )
                findings.append(finding)
        else:
            # Check supplied credentials against known defaults
            for username, password in creds_to_check:
                for def_user, def_pass in known_defaults:
                    if username == def_user and password == def_pass:
                        finding = CredentialFinding(
                            device_id=device.id,
                            manufacturer=device.manufacturer,
                            username=username,
                            credential_type="password",
                            is_default=True,
                            risk_level=RiskLevel.CRITICAL,
                            recommendation=(
                                f"Default credentials confirmed for {device.manufacturer}. "
                                "Change immediately to a unique strong password."
                            ),
                        )
                        findings.append(finding)

        with self._lock, self._conn() as conn:
            for f in findings:
                conn.execute(
                    "INSERT INTO credential_findings (id, device_id, data, detected_at) VALUES (?,?,?,?)",
                    (f.id, device.id, f.model_dump_json(), f.detected_at.isoformat()),
                )

        logger.info("credentials_checked", device_id=device.id, default_count=len(findings))
        return findings

    def get_credential_findings(self, device_id: str) -> List[CredentialFinding]:
        """Get all credential findings for a device."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM credential_findings WHERE device_id=? ORDER BY detected_at DESC",
                (device_id,),
            ).fetchall()
        return [CredentialFinding.model_validate_json(r["data"]) for r in rows]

    # ------------------------------------------------------------------
    # Communication pattern analysis
    # ------------------------------------------------------------------

    def record_communication(self, pattern: CommunicationPattern) -> CommunicationPattern:
        """Record a communication pattern for a device."""
        with self._lock, self._conn() as conn:
            # Check for existing pattern (same device+remote+port+protocol)
            existing = conn.execute(
                """SELECT id, data FROM communication_patterns
                   WHERE device_id=? AND json_extract(data,'$.remote_ip')=?
                     AND json_extract(data,'$.remote_port')=?
                     AND json_extract(data,'$.protocol')=?""",
                (pattern.device_id, pattern.remote_ip, pattern.remote_port, pattern.protocol),
            ).fetchone()

            if existing:
                old = CommunicationPattern.model_validate_json(existing["data"])
                old.bytes_sent += pattern.bytes_sent
                old.bytes_received += pattern.bytes_received
                old.connection_count += 1
                old.last_seen = pattern.last_seen
                conn.execute(
                    "UPDATE communication_patterns SET last_seen=?, data=? WHERE id=?",
                    (old.last_seen.isoformat(), old.model_dump_json(), old.id),
                )
                return old
            else:
                conn.execute(
                    "INSERT INTO communication_patterns (id, device_id, org_id, data, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
                    (
                        pattern.id, pattern.device_id, pattern.org_id,
                        pattern.model_dump_json(),
                        pattern.first_seen.isoformat(),
                        pattern.last_seen.isoformat(),
                    ),
                )
        return pattern

    def analyse_communications(self, device_id: str) -> List[CommunicationAnomaly]:
        """Analyse communication patterns to detect C2 beaconing and data exfiltration."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM communication_patterns WHERE device_id=? ORDER BY first_seen DESC",
                (device_id,),
            ).fetchall()

        patterns = [CommunicationPattern.model_validate_json(r["data"]) for r in rows]
        anomalies: List[CommunicationAnomaly] = []

        # C2 beaconing detection: regular high-frequency connections to same remote
        for p in patterns:
            if p.connection_count > 50:
                time_span = (p.last_seen - p.first_seen).total_seconds()
                if time_span > 0:
                    rate = p.connection_count / (time_span / 3600)  # per hour
                    if rate > 20:  # more than 20 connections per hour
                        confidence = min(1.0, rate / 100)
                        anomaly = CommunicationAnomaly(
                            device_id=device_id,
                            anomaly_type="c2_beaconing",
                            remote_ip=p.remote_ip,
                            remote_port=p.remote_port,
                            confidence=confidence,
                            risk_level=RiskLevel.CRITICAL if confidence > 0.7 else RiskLevel.HIGH,
                            evidence={
                                "connection_count": p.connection_count,
                                "rate_per_hour": round(rate, 2),
                                "protocol": p.protocol,
                                "time_span_hours": round(time_span / 3600, 2),
                            },
                        )
                        anomalies.append(anomaly)

            # Data exfiltration detection: high outbound bytes to external IP
            # Heuristic: sent > 100MB and sent > 10x received suggests exfiltration
            if p.bytes_sent > 100 * 1024 * 1024:
                ratio = p.bytes_sent / max(p.bytes_received, 1)
                if ratio > 10:
                    confidence = min(1.0, ratio / 100)
                    anomaly = CommunicationAnomaly(
                        device_id=device_id,
                        anomaly_type="data_exfiltration",
                        remote_ip=p.remote_ip,
                        remote_port=p.remote_port,
                        confidence=confidence,
                        risk_level=RiskLevel.CRITICAL,
                        evidence={
                            "bytes_sent_mb": round(p.bytes_sent / (1024 * 1024), 2),
                            "bytes_received_mb": round(p.bytes_received / (1024 * 1024), 2),
                            "send_receive_ratio": round(ratio, 2),
                            "protocol": p.protocol,
                        },
                    )
                    anomalies.append(anomaly)

        with self._lock, self._conn() as conn:
            for a in anomalies:
                conn.execute(
                    "INSERT INTO communication_anomalies (id, device_id, data, detected_at) VALUES (?,?,?,?)",
                    (a.id, device_id, a.model_dump_json(), a.detected_at.isoformat()),
                )

        logger.info("comms_analysed", device_id=device_id, anomalies=len(anomalies))
        return anomalies

    def get_communication_anomalies(self, device_id: str) -> List[CommunicationAnomaly]:
        """Get all communication anomalies for a device."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM communication_anomalies WHERE device_id=? ORDER BY detected_at DESC",
                (device_id,),
            ).fetchall()
        return [CommunicationAnomaly.model_validate_json(r["data"]) for r in rows]

    # ------------------------------------------------------------------
    # Compliance mapping
    # ------------------------------------------------------------------

    def assess_compliance(self, device: IoTDevice,
                          framework: ComplianceFramework) -> List[ComplianceResult]:
        """Assess a device against a compliance framework."""
        controls = _COMPLIANCE_CONTROLS.get(framework, [])
        results: List[ComplianceResult] = []

        # Gather current finding state
        fw_findings = self.get_firmware_findings(device.id)
        proto_findings = self.get_protocol_findings(device.id)
        seg_findings = self.get_segmentation_findings(device.id)
        cred_findings = self.get_credential_findings(device.id)
        anomalies = self.get_communication_anomalies(device.id)

        has_cves = any(f.cves for f in fw_findings)
        firmware_eol = any(f.is_end_of_life for f in fw_findings)
        has_insecure_proto = any(f.is_insecure for f in proto_findings)
        has_seg_violation = any(f.is_violation for f in seg_findings)
        has_default_creds = any(f.is_default for f in cred_findings)
        has_c2 = any(a.anomaly_type == "c2_beaconing" for a in anomalies)

        check_map: Dict[str, Tuple[bool, str, str]] = {
            # check_name -> (passes, details, remediation)
            "has_unique_id": (
                bool(device.mac_address or device.id),
                "Device has unique identifier" if device.mac_address else "No MAC address recorded",
                "Record device MAC address for unique identification",
            ),
            "no_default_credentials": (
                not has_default_creds,
                "No default credentials detected" if not has_default_creds else f"Default credentials found for {device.manufacturer}",
                "Change all default credentials immediately",
            ),
            "firmware_current": (
                not has_cves and not firmware_eol,
                "Firmware is current" if not has_cves and not firmware_eol else "Firmware has CVEs or is EOL",
                "Update firmware to latest version and apply all security patches",
            ),
            "secure_protocols": (
                not has_insecure_proto,
                "All protocols are secure" if not has_insecure_proto else "Insecure protocols detected",
                "Disable insecure protocols (Telnet, HTTP, MQTT) and enable encrypted equivalents",
            ),
            "network_segmented": (
                not has_seg_violation,
                "Device is correctly segmented" if not has_seg_violation else "Segmentation violation detected",
                "Move device to appropriate isolated network segment/VLAN",
            ),
            "proper_vlan": (
                device.vlan_id is not None,
                f"Device on VLAN {device.vlan_id}" if device.vlan_id else "No VLAN assignment",
                "Assign device to a dedicated IoT/OT VLAN",
            ),
            "no_c2_beaconing": (
                not has_c2,
                "No C2 beaconing detected" if not has_c2 else "C2 beaconing anomaly detected",
                "Investigate and block suspicious outbound connections",
            ),
        }

        for control in controls:
            check = control["check"]
            if check in check_map:
                passes, details, remediation = check_map[check]
                status = "pass" if passes else "fail"
            else:
                status = "not_applicable"
                details = "Check not applicable for this device type"
                remediation = ""

            result = ComplianceResult(
                device_id=device.id,
                framework=framework,
                control_id=control["id"],
                control_name=control["name"],
                status=status,
                details=details,
                remediation=remediation if status == "fail" else "",
            )
            results.append(result)

        with self._lock, self._conn() as conn:
            # Clear previous results for this device+framework
            conn.execute(
                "DELETE FROM compliance_results WHERE device_id=? AND framework=?",
                (device.id, framework.value),
            )
            for r in results:
                conn.execute(
                    "INSERT INTO compliance_results (id, device_id, framework, data, assessed_at) VALUES (?,?,?,?,?)",
                    (r.id, device.id, framework.value, r.model_dump_json(), r.assessed_at.isoformat()),
                )

        passed = sum(1 for r in results if r.status == "pass")
        logger.info("compliance_assessed", device_id=device.id, framework=framework.value,
                    passed=passed, total=len(results))
        return results

    def get_compliance_results(self, device_id: str,
                               framework: Optional[ComplianceFramework] = None) -> List[ComplianceResult]:
        """Get compliance results for a device, optionally filtered by framework."""
        with self._conn() as conn:
            if framework:
                rows = conn.execute(
                    "SELECT data FROM compliance_results WHERE device_id=? AND framework=? ORDER BY assessed_at DESC",
                    (device_id, framework.value),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM compliance_results WHERE device_id=? ORDER BY assessed_at DESC",
                    (device_id,),
                ).fetchall()
        return [ComplianceResult.model_validate_json(r["data"]) for r in rows]

    # ------------------------------------------------------------------
    # Full device scan
    # ------------------------------------------------------------------

    def scan_device(self, device_id: str,
                    frameworks: Optional[List[ComplianceFramework]] = None) -> DeviceScanResult:
        """Run a comprehensive security scan on a device."""
        device = self.get_device(device_id)
        if device is None:
            raise ValueError(f"Device {device_id} not found")

        if frameworks is None:
            frameworks = [ComplianceFramework.NIST_IOT]
            if device.device_type in {DeviceType.PLC, DeviceType.SCADA, DeviceType.HMI}:
                frameworks.append(ComplianceFramework.IEC_62443)
            if device.device_type == DeviceType.MEDICAL:
                frameworks.append(ComplianceFramework.FDA_MEDICAL)

        fw_finding = self.analyse_firmware(device)
        proto_findings = self.check_protocols(device)
        seg_finding = self.verify_segmentation(device)
        cred_findings = self.check_default_credentials(device)
        comm_anomalies = self.analyse_communications(device_id)

        all_compliance: List[ComplianceResult] = []
        for fw in frameworks:
            all_compliance.extend(self.assess_compliance(device, fw))

        # Calculate risk score
        risk_score = 0.0
        if fw_finding.cves:
            risk_score += _RISK_WEIGHTS["firmware_critical_cve"]
        if fw_finding.is_end_of_life:
            risk_score += _RISK_WEIGHTS["firmware_eol"]
        for pf in proto_findings:
            if pf.risk_level == RiskLevel.CRITICAL:
                risk_score += _RISK_WEIGHTS["insecure_protocol_critical"]
            elif pf.risk_level == RiskLevel.HIGH:
                risk_score += _RISK_WEIGHTS["insecure_protocol_high"]
        if cred_findings:
            risk_score += _RISK_WEIGHTS["default_credentials"]
        if seg_finding.is_violation:
            risk_score += _RISK_WEIGHTS["segmentation_violation"]
        for a in comm_anomalies:
            if a.anomaly_type == "c2_beaconing":
                risk_score += _RISK_WEIGHTS["c2_beaconing"]
            elif a.anomaly_type == "data_exfiltration":
                risk_score += _RISK_WEIGHTS["data_exfiltration"]

        risk_score = min(100.0, risk_score)

        # Determine overall risk level
        if risk_score >= 70:
            overall_risk = RiskLevel.CRITICAL
        elif risk_score >= 50:
            overall_risk = RiskLevel.HIGH
        elif risk_score >= 25:
            overall_risk = RiskLevel.MEDIUM
        elif risk_score > 0:
            overall_risk = RiskLevel.LOW
        else:
            overall_risk = RiskLevel.INFO

        # Update device risk score
        device.risk_score = risk_score
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE devices SET data=? WHERE id=?",
                (device.model_dump_json(), device_id),
            )

        summary_parts = [f"Risk score: {risk_score:.1f}/100 ({overall_risk.value.upper()})"]
        if fw_finding.cves:
            summary_parts.append(f"{len(fw_finding.cves)} firmware CVEs")
        if proto_findings:
            summary_parts.append(f"{len(proto_findings)} insecure protocols")
        if cred_findings:
            summary_parts.append("default credentials detected")
        if seg_finding.is_violation:
            summary_parts.append("segmentation violation")
        if comm_anomalies:
            summary_parts.append(f"{len(comm_anomalies)} communication anomalies")

        result = DeviceScanResult(
            device_id=device_id,
            firmware_findings=[fw_finding],
            protocol_findings=proto_findings,
            segmentation_findings=[seg_finding],
            credential_findings=cred_findings,
            communication_anomalies=comm_anomalies,
            compliance_results=all_compliance,
            overall_risk=overall_risk,
            risk_score=risk_score,
            summary=". ".join(summary_parts),
        )

        logger.info("device_scanned", device_id=device_id, risk_score=risk_score, risk=overall_risk.value)
        _emit_event("iot.device_scanned", {"device_id": device_id, "risk_score": risk_score, "risk": overall_risk.value})
        return result

    # ------------------------------------------------------------------
    # Summary / stats
    # ------------------------------------------------------------------

    def get_summary(self, org_id: str = "default") -> IoTSummary:
        """Get IoT security summary for an organisation."""
        devices = self.list_devices(org_id)

        by_type: Dict[str, int] = {}
        by_segment: Dict[str, int] = {}
        by_risk: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for d in devices:
            by_type[d.device_type.value] = by_type.get(d.device_type.value, 0) + 1
            by_segment[d.network_segment.value] = by_segment.get(d.network_segment.value, 0) + 1
            if d.risk_score >= 70:
                by_risk["critical"] += 1
            elif d.risk_score >= 50:
                by_risk["high"] += 1
            elif d.risk_score >= 25:
                by_risk["medium"] += 1
            elif d.risk_score > 0:
                by_risk["low"] += 1
            else:
                by_risk["info"] += 1

        # Count finding categories
        critical_findings = 0
        high_findings = 0
        seg_violations = 0
        default_cred_devices = 0
        eol_devices = 0
        insecure_proto_devices = 0

        with self._conn() as conn:
            for d in devices:
                fw_rows = conn.execute(
                    "SELECT data FROM firmware_findings WHERE device_id=?", (d.id,)
                ).fetchall()
                for row in fw_rows:
                    f = FirmwareFinding.model_validate_json(row["data"])
                    if f.risk_level == RiskLevel.CRITICAL:
                        critical_findings += 1
                    elif f.risk_level == RiskLevel.HIGH:
                        high_findings += 1
                    if f.is_end_of_life:
                        eol_devices += 1
                        break

                proto_rows = conn.execute(
                    "SELECT data FROM protocol_findings WHERE device_id=?", (d.id,)
                ).fetchall()
                if any(ProtocolFinding.model_validate_json(r["data"]).is_insecure for r in proto_rows):
                    insecure_proto_devices += 1

                seg_rows = conn.execute(
                    "SELECT data FROM segmentation_findings WHERE device_id=?", (d.id,)
                ).fetchall()
                if any(SegmentationFinding.model_validate_json(r["data"]).is_violation for r in seg_rows):
                    seg_violations += 1

                cred_rows = conn.execute(
                    "SELECT data FROM credential_findings WHERE device_id=?", (d.id,)
                ).fetchall()
                if any(CredentialFinding.model_validate_json(r["data"]).is_default for r in cred_rows):
                    default_cred_devices += 1

        return IoTSummary(
            org_id=org_id,
            total_devices=len(devices),
            devices_by_type=by_type,
            devices_by_segment=by_segment,
            devices_by_risk=by_risk,
            critical_findings=critical_findings,
            high_findings=high_findings,
            segmentation_violations=seg_violations,
            default_credential_devices=default_cred_devices,
            eol_firmware_devices=eol_devices,
            insecure_protocol_devices=insecure_proto_devices,
        )


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine: Optional[IoTSecurityEngine] = None
_engine_lock = threading.Lock()


def get_iot_engine(db_path: str = _DEFAULT_DB) -> IoTSecurityEngine:
    """Return the singleton IoTSecurityEngine instance."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = IoTSecurityEngine(db_path=db_path)
    return _engine
