"""Comprehensive test suite for ALDECI IoT/OT Security Scanner.

Tests cover:
- IoTDevice model validation
- IoTSecurityEngine: device CRUD, firmware analysis, protocol checks,
  segmentation verification, credential detection, communication pattern
  analysis, compliance mapping, full device scan, summary generation
- Router: all 8 endpoints with correct response shapes and error handling

50+ tests, all using in-memory SQLite (tmpdir), no external dependencies.
"""

from __future__ import annotations

import sys
import tempfile
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.iot_security import (
    CommunicationPattern,
    ComplianceFramework,
    ComplianceResult,
    CredentialFinding,
    DeviceProtocol,
    DeviceScanResult,
    DeviceType,
    FirmwareFinding,
    IoTDevice,
    IoTSecurityEngine,
    IoTSummary,
    NetworkSegment,
    ProtocolFinding,
    RiskLevel,
    SegmentationFinding,
    get_iot_engine,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def engine() -> IoTSecurityEngine:
    """Create an IoTSecurityEngine backed by a temp SQLite database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_iot.db")
        yield IoTSecurityEngine(db_path=db_path)


@pytest.fixture
def camera_device(engine: IoTSecurityEngine) -> IoTDevice:
    """Register a Hikvision camera with known-vulnerable firmware."""
    device = IoTDevice(
        name="Lobby Camera",
        device_type=DeviceType.CAMERA,
        manufacturer="hikvision",
        model="DS-2CD2143G0-I",
        firmware_version="5.5.0",
        ip_address="192.168.10.5",
        mac_address="AA:BB:CC:DD:EE:FF",
        network_segment=NetworkSegment.CORPORATE,  # violation
        vlan_id=None,
        protocols=[DeviceProtocol.HTTP, DeviceProtocol.TELNET],
        open_ports=[80, 23, 554],
        org_id="test-org",
    )
    return engine.register_device(device)


@pytest.fixture
def plc_device(engine: IoTSecurityEngine) -> IoTDevice:
    """Register a Siemens PLC in the OT network."""
    device = IoTDevice(
        name="Assembly Line PLC",
        device_type=DeviceType.PLC,
        manufacturer="siemens",
        model="S7-1200",
        firmware_version="4.0.0",
        ip_address="10.0.100.50",
        mac_address="11:22:33:44:55:66",
        network_segment=NetworkSegment.OT_NETWORK,
        protocols=[DeviceProtocol.MODBUS, DeviceProtocol.PROFINET],
        open_ports=[502],
        org_id="test-org",
    )
    return engine.register_device(device)


@pytest.fixture
def medical_device(engine: IoTSecurityEngine) -> IoTDevice:
    """Register a Philips medical device."""
    device = IoTDevice(
        name="Patient Monitor",
        device_type=DeviceType.MEDICAL,
        manufacturer="philips",
        model="IntelliVue MX450",
        firmware_version="1.0.0",
        ip_address="172.16.50.10",
        network_segment=NetworkSegment.CORPORATE,  # violation for medical
        protocols=[DeviceProtocol.HTTP, DeviceProtocol.MQTT],
        open_ports=[80, 1883],
        org_id="test-org",
    )
    return engine.register_device(device)


@pytest.fixture
def clean_device(engine: IoTSecurityEngine) -> IoTDevice:
    """Register a properly configured device."""
    device = IoTDevice(
        name="Secure Sensor",
        device_type=DeviceType.SENSOR,
        manufacturer="unknown_vendor",
        model="SecureSensor-X1",
        firmware_version="3.0.0",
        ip_address="10.1.20.30",
        mac_address="DE:AD:BE:EF:00:01",
        network_segment=NetworkSegment.IOT_VLAN,
        vlan_id=200,
        protocols=[DeviceProtocol.MQTTS, DeviceProtocol.COAPS],
        open_ports=[8883],
        org_id="test-org",
    )
    return engine.register_device(device)


# ============================================================================
# IoTDevice model tests
# ============================================================================


class TestIoTDeviceModel:
    def test_device_defaults(self) -> None:
        device = IoTDevice(
            name="Test",
            device_type=DeviceType.SENSOR,
            manufacturer="acme",
            ip_address="1.2.3.4",
        )
        assert device.id is not None
        assert device.org_id == "default"
        assert device.risk_score == 0.0
        assert device.protocols == []
        assert device.network_segment == NetworkSegment.UNKNOWN

    def test_device_id_unique(self) -> None:
        d1 = IoTDevice(name="A", device_type=DeviceType.SENSOR, manufacturer="x", ip_address="1.1.1.1")
        d2 = IoTDevice(name="B", device_type=DeviceType.SENSOR, manufacturer="x", ip_address="1.1.1.2")
        assert d1.id != d2.id

    def test_device_enum_values(self) -> None:
        assert DeviceType.PLC.value == "plc"
        assert DeviceType.MEDICAL.value == "medical"
        assert NetworkSegment.CORPORATE.value == "corporate"
        assert DeviceProtocol.TELNET.value == "telnet"

    def test_device_serialisation_round_trip(self) -> None:
        device = IoTDevice(
            name="RoundTrip",
            device_type=DeviceType.CAMERA,
            manufacturer="hikvision",
            firmware_version="5.5.0",
            ip_address="10.0.0.1",
            protocols=[DeviceProtocol.HTTP, DeviceProtocol.MQTT],
        )
        data = device.model_dump_json()
        restored = IoTDevice.model_validate_json(data)
        assert restored.id == device.id
        assert restored.name == device.name
        assert restored.protocols == device.protocols


# ============================================================================
# Device inventory tests
# ============================================================================


class TestDeviceInventory:
    def test_register_device(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        assert camera_device.id is not None
        assert camera_device.name == "Lobby Camera"

    def test_get_device_by_id(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        fetched = engine.get_device(camera_device.id)
        assert fetched is not None
        assert fetched.id == camera_device.id
        assert fetched.manufacturer == "hikvision"

    def test_get_device_not_found(self, engine: IoTSecurityEngine) -> None:
        result = engine.get_device("non-existent-id")
        assert result is None

    def test_list_devices_by_org(self, engine: IoTSecurityEngine,
                                  camera_device: IoTDevice, plc_device: IoTDevice) -> None:
        devices = engine.list_devices(org_id="test-org")
        ids = [d.id for d in devices]
        assert camera_device.id in ids
        assert plc_device.id in ids

    def test_list_devices_filter_by_type(self, engine: IoTSecurityEngine,
                                          camera_device: IoTDevice, plc_device: IoTDevice) -> None:
        cameras = engine.list_devices(org_id="test-org", device_type=DeviceType.CAMERA)
        assert all(d.device_type == DeviceType.CAMERA for d in cameras)
        assert camera_device.id in [d.id for d in cameras]

    def test_list_devices_filter_by_segment(self, engine: IoTSecurityEngine,
                                             camera_device: IoTDevice, clean_device: IoTDevice) -> None:
        iot_devices = engine.list_devices(org_id="test-org", network_segment=NetworkSegment.IOT_VLAN)
        assert clean_device.id in [d.id for d in iot_devices]
        assert camera_device.id not in [d.id for d in iot_devices]

    def test_list_devices_different_org(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        other_org_devices = engine.list_devices(org_id="other-org")
        assert camera_device.id not in [d.id for d in other_org_devices]

    def test_update_device_last_seen(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.update_device_last_seen(camera_device.id)
        updated = engine.get_device(camera_device.id)
        assert updated is not None
        assert updated.last_seen is not None

    def test_update_last_seen_nonexistent(self, engine: IoTSecurityEngine) -> None:
        # Should not raise
        engine.update_device_last_seen("does-not-exist")


# ============================================================================
# Firmware analysis tests
# ============================================================================


class TestFirmwareAnalysis:
    def test_known_cves_detected(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        finding = engine.analyse_firmware(camera_device)
        assert len(finding.cves) > 0
        assert "CVE-2017-7921" in finding.cves or "CVE-2021-36260" in finding.cves

    def test_eol_firmware_detected(self, engine: IoTSecurityEngine) -> None:
        device = IoTDevice(
            name="EOL Cam", device_type=DeviceType.CAMERA, manufacturer="hikvision",
            firmware_version="5.3.0", ip_address="1.2.3.4", org_id="test-org",
        )
        engine.register_device(device)
        finding = engine.analyse_firmware(device)
        assert finding.is_end_of_life is True

    def test_update_available(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        finding = engine.analyse_firmware(camera_device)
        assert finding.update_available is not None

    def test_clean_firmware_no_cves(self, engine: IoTSecurityEngine, clean_device: IoTDevice) -> None:
        finding = engine.analyse_firmware(clean_device)
        assert finding.cves == []
        assert finding.is_end_of_life is False

    def test_firmware_risk_critical_when_cves_and_eol(self, engine: IoTSecurityEngine) -> None:
        device = IoTDevice(
            name="EOL CVE Cam", device_type=DeviceType.CAMERA, manufacturer="hikvision",
            firmware_version="5.3.0", ip_address="1.2.3.4", org_id="test-org",
        )
        engine.register_device(device)
        finding = engine.analyse_firmware(device)
        assert finding.risk_level == RiskLevel.CRITICAL

    def test_firmware_finding_stored(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.analyse_firmware(camera_device)
        findings = engine.get_firmware_findings(camera_device.id)
        assert len(findings) >= 1

    def test_get_firmware_findings_empty(self, engine: IoTSecurityEngine, clean_device: IoTDevice) -> None:
        findings = engine.get_firmware_findings(clean_device.id)
        assert findings == []


# ============================================================================
# Protocol security tests
# ============================================================================


class TestProtocolSecurity:
    def test_telnet_detected_as_insecure(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        findings = engine.check_protocols(camera_device)
        protocols = [f.protocol for f in findings]
        assert DeviceProtocol.TELNET in protocols

    def test_http_detected_as_insecure(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        findings = engine.check_protocols(camera_device)
        protocols = [f.protocol for f in findings]
        assert DeviceProtocol.HTTP in protocols

    def test_mqtt_without_tls_is_insecure(self, engine: IoTSecurityEngine, medical_device: IoTDevice) -> None:
        findings = engine.check_protocols(medical_device)
        protocols = [f.protocol for f in findings]
        assert DeviceProtocol.MQTT in protocols

    def test_secure_protocols_no_findings(self, engine: IoTSecurityEngine, clean_device: IoTDevice) -> None:
        findings = engine.check_protocols(clean_device)
        assert all(not f.is_insecure for f in findings)

    def test_port_23_triggers_telnet_finding(self, engine: IoTSecurityEngine) -> None:
        device = IoTDevice(
            name="Port23 Device", device_type=DeviceType.ROUTER, manufacturer="cisco",
            ip_address="10.0.0.1", open_ports=[23], protocols=[], org_id="test-org",
        )
        engine.register_device(device)
        findings = engine.check_protocols(device)
        telnet_findings = [f for f in findings if f.protocol == DeviceProtocol.TELNET]
        assert len(telnet_findings) >= 1

    def test_telnet_finding_is_critical(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        findings = engine.check_protocols(camera_device)
        telnet = [f for f in findings if f.protocol == DeviceProtocol.TELNET]
        assert len(telnet) > 0
        assert telnet[0].risk_level == RiskLevel.CRITICAL

    def test_protocol_findings_stored(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.check_protocols(camera_device)
        stored = engine.get_protocol_findings(camera_device.id)
        assert len(stored) > 0

    def test_snmp_is_medium_risk(self, engine: IoTSecurityEngine) -> None:
        device = IoTDevice(
            name="SNMP Device", device_type=DeviceType.ROUTER, manufacturer="cisco",
            ip_address="10.0.0.2", protocols=[DeviceProtocol.SNMP], org_id="test-org",
        )
        engine.register_device(device)
        findings = engine.check_protocols(device)
        snmp = [f for f in findings if f.protocol == DeviceProtocol.SNMP]
        assert len(snmp) > 0
        assert snmp[0].risk_level == RiskLevel.MEDIUM


# ============================================================================
# Network segmentation tests
# ============================================================================


class TestNetworkSegmentation:
    def test_iot_on_corporate_is_violation(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        finding = engine.verify_segmentation(camera_device)
        assert finding.is_violation is True
        assert finding.risk_level == RiskLevel.HIGH

    def test_plc_on_ot_network_is_ok(self, engine: IoTSecurityEngine, plc_device: IoTDevice) -> None:
        finding = engine.verify_segmentation(plc_device)
        assert finding.is_violation is False

    def test_medical_on_corporate_is_critical(self, engine: IoTSecurityEngine, medical_device: IoTDevice) -> None:
        finding = engine.verify_segmentation(medical_device)
        assert finding.is_violation is True
        assert finding.risk_level == RiskLevel.CRITICAL

    def test_plc_on_corporate_is_critical(self, engine: IoTSecurityEngine) -> None:
        device = IoTDevice(
            name="PLC on corp", device_type=DeviceType.PLC, manufacturer="siemens",
            ip_address="192.168.1.100", network_segment=NetworkSegment.CORPORATE,
            org_id="test-org",
        )
        engine.register_device(device)
        finding = engine.verify_segmentation(device)
        assert finding.risk_level == RiskLevel.CRITICAL

    def test_sensor_on_iot_vlan_is_ok(self, engine: IoTSecurityEngine, clean_device: IoTDevice) -> None:
        finding = engine.verify_segmentation(clean_device)
        assert finding.is_violation is False

    def test_segmentation_finding_stored(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.verify_segmentation(camera_device)
        findings = engine.get_segmentation_findings(camera_device.id)
        assert len(findings) >= 1


# ============================================================================
# Default credential tests
# ============================================================================


class TestDefaultCredentials:
    def test_known_manufacturer_flags_defaults(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        findings = engine.check_default_credentials(camera_device)
        assert len(findings) > 0
        assert all(f.is_default for f in findings)

    def test_confirmed_default_credential(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        findings = engine.check_default_credentials(
            camera_device, supplied_credentials=[("admin", "12345")]
        )
        assert len(findings) == 1
        assert findings[0].is_default is True
        assert findings[0].risk_level == RiskLevel.CRITICAL

    def test_non_default_credential_not_flagged(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        findings = engine.check_default_credentials(
            camera_device, supplied_credentials=[("admin", "S3cur3P@ssw0rd!")]
        )
        assert len(findings) == 0

    def test_unknown_manufacturer_no_defaults(self, engine: IoTSecurityEngine, clean_device: IoTDevice) -> None:
        findings = engine.check_default_credentials(clean_device)
        assert len(findings) == 0

    def test_credential_findings_stored(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.check_default_credentials(camera_device)
        stored = engine.get_credential_findings(camera_device.id)
        assert len(stored) > 0


# ============================================================================
# Communication pattern analysis tests
# ============================================================================


class TestCommunicationAnalysis:
    def test_record_communication_pattern(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        now = datetime.now(timezone.utc)
        pattern = CommunicationPattern(
            device_id=camera_device.id,
            remote_ip="203.0.113.1",
            remote_port=4444,
            protocol="tcp",
            bytes_sent=1000,
            bytes_received=200,
            connection_count=1,
            first_seen=now,
            last_seen=now,
            org_id="test-org",
        )
        recorded = engine.record_communication(pattern)
        assert recorded.device_id == camera_device.id

    def test_communication_aggregation(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        now = datetime.now(timezone.utc)
        for _ in range(3):
            pattern = CommunicationPattern(
                device_id=camera_device.id,
                remote_ip="203.0.113.1",
                remote_port=4444,
                protocol="tcp",
                bytes_sent=500,
                bytes_received=100,
                first_seen=now,
                last_seen=now,
                org_id="test-org",
            )
            engine.record_communication(pattern)

    def test_c2_beaconing_detected(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        """High-frequency connections should trigger C2 beaconing anomaly."""
        start = datetime.now(timezone.utc) - timedelta(hours=2)
        end = datetime.now(timezone.utc)
        pattern = CommunicationPattern(
            device_id=camera_device.id,
            remote_ip="198.51.100.99",
            remote_port=443,
            protocol="tcp",
            bytes_sent=50000,
            bytes_received=5000,
            connection_count=200,  # 200 connections in 2 hours = 100/hr
            first_seen=start,
            last_seen=end,
            org_id="test-org",
        )
        engine.record_communication(pattern)
        anomalies = engine.analyse_communications(camera_device.id)
        c2_anomalies = [a for a in anomalies if a.anomaly_type == "c2_beaconing"]
        assert len(c2_anomalies) >= 1

    def test_data_exfiltration_detected(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        """High outbound bytes with low inbound should trigger data exfiltration anomaly."""
        now = datetime.now(timezone.utc)
        pattern = CommunicationPattern(
            device_id=camera_device.id,
            remote_ip="198.51.100.50",
            remote_port=8080,
            protocol="tcp",
            bytes_sent=500 * 1024 * 1024,  # 500 MB sent
            bytes_received=1024,  # 1 KB received
            connection_count=10,
            first_seen=now - timedelta(hours=1),
            last_seen=now,
            org_id="test-org",
        )
        engine.record_communication(pattern)
        anomalies = engine.analyse_communications(camera_device.id)
        exfil_anomalies = [a for a in anomalies if a.anomaly_type == "data_exfiltration"]
        assert len(exfil_anomalies) >= 1

    def test_normal_communications_no_anomalies(self, engine: IoTSecurityEngine, clean_device: IoTDevice) -> None:
        now = datetime.now(timezone.utc)
        pattern = CommunicationPattern(
            device_id=clean_device.id,
            remote_ip="10.0.0.1",
            remote_port=8883,
            protocol="tcp",
            bytes_sent=1024,
            bytes_received=512,
            connection_count=5,
            first_seen=now - timedelta(hours=1),
            last_seen=now,
            org_id="test-org",
        )
        engine.record_communication(pattern)
        anomalies = engine.analyse_communications(clean_device.id)
        assert len(anomalies) == 0

    def test_get_communication_anomalies_empty(self, engine: IoTSecurityEngine, clean_device: IoTDevice) -> None:
        anomalies = engine.get_communication_anomalies(clean_device.id)
        assert anomalies == []


# ============================================================================
# Compliance mapping tests
# ============================================================================


class TestComplianceMapping:
    def test_nist_iot_compliance(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        results = engine.assess_compliance(camera_device, ComplianceFramework.NIST_IOT)
        assert len(results) > 0
        control_ids = [r.control_id for r in results]
        assert "NIST-IOT-1.1" in control_ids

    def test_iec_62443_compliance(self, engine: IoTSecurityEngine, plc_device: IoTDevice) -> None:
        results = engine.assess_compliance(plc_device, ComplianceFramework.IEC_62443)
        assert len(results) > 0
        control_ids = [r.control_id for r in results]
        assert "IEC-62443-SR-5.1" in control_ids

    def test_fda_medical_compliance(self, engine: IoTSecurityEngine, medical_device: IoTDevice) -> None:
        # Run a scan first to populate findings
        engine.analyse_firmware(medical_device)
        engine.check_protocols(medical_device)
        engine.verify_segmentation(medical_device)
        engine.check_default_credentials(medical_device)
        results = engine.assess_compliance(medical_device, ComplianceFramework.FDA_MEDICAL)
        assert len(results) > 0
        control_ids = [r.control_id for r in results]
        assert "FDA-CYBER-1" in control_ids

    def test_compliance_fails_when_findings_present(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.check_protocols(camera_device)
        engine.verify_segmentation(camera_device)
        engine.check_default_credentials(camera_device)
        results = engine.assess_compliance(camera_device, ComplianceFramework.NIST_IOT)
        failed = [r for r in results if r.status == "fail"]
        assert len(failed) > 0

    def test_compliance_passes_for_clean_device(self, engine: IoTSecurityEngine, clean_device: IoTDevice) -> None:
        results = engine.assess_compliance(clean_device, ComplianceFramework.NIST_IOT)
        # At minimum has_unique_id should pass (has MAC)
        passed = [r for r in results if r.status == "pass"]
        assert len(passed) > 0

    def test_get_compliance_results_by_framework(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.assess_compliance(camera_device, ComplianceFramework.NIST_IOT)
        engine.assess_compliance(camera_device, ComplianceFramework.IEC_62443)
        nist_only = engine.get_compliance_results(camera_device.id, framework=ComplianceFramework.NIST_IOT)
        assert all(r.framework == ComplianceFramework.NIST_IOT for r in nist_only)

    def test_get_compliance_results_all_frameworks(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.assess_compliance(camera_device, ComplianceFramework.NIST_IOT)
        engine.assess_compliance(camera_device, ComplianceFramework.IEC_62443)
        all_results = engine.get_compliance_results(camera_device.id)
        frameworks = {r.framework for r in all_results}
        assert ComplianceFramework.NIST_IOT in frameworks
        assert ComplianceFramework.IEC_62443 in frameworks

    def test_compliance_results_stored(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.assess_compliance(camera_device, ComplianceFramework.NIST_IOT)
        stored = engine.get_compliance_results(camera_device.id)
        assert len(stored) > 0

    def test_compliance_idempotent(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        """Re-running compliance should replace old results."""
        engine.assess_compliance(camera_device, ComplianceFramework.NIST_IOT)
        engine.assess_compliance(camera_device, ComplianceFramework.NIST_IOT)
        results = engine.get_compliance_results(camera_device.id, ComplianceFramework.NIST_IOT)
        # Should not double up
        control_ids = [r.control_id for r in results]
        assert len(control_ids) == len(set(control_ids))


# ============================================================================
# Full device scan tests
# ============================================================================


class TestDeviceScan:
    def test_scan_returns_result(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        result = engine.scan_device(camera_device.id)
        assert isinstance(result, DeviceScanResult)
        assert result.device_id == camera_device.id

    def test_scan_includes_firmware_findings(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        result = engine.scan_device(camera_device.id)
        assert len(result.firmware_findings) > 0

    def test_scan_includes_protocol_findings(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        result = engine.scan_device(camera_device.id)
        assert len(result.protocol_findings) > 0

    def test_scan_includes_segmentation_findings(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        result = engine.scan_device(camera_device.id)
        assert len(result.segmentation_findings) > 0

    def test_scan_includes_credential_findings(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        result = engine.scan_device(camera_device.id)
        assert len(result.credential_findings) > 0

    def test_scan_risk_score_not_zero_for_bad_device(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        result = engine.scan_device(camera_device.id)
        assert result.risk_score > 0.0

    def test_scan_risk_score_capped_at_100(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        result = engine.scan_device(camera_device.id)
        assert result.risk_score <= 100.0

    def test_scan_overall_risk_high_or_critical_for_bad_device(self, engine: IoTSecurityEngine,
                                                                 camera_device: IoTDevice) -> None:
        result = engine.scan_device(camera_device.id)
        assert result.overall_risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}

    def test_scan_updates_device_risk_score(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        result = engine.scan_device(camera_device.id)
        updated = engine.get_device(camera_device.id)
        assert updated is not None
        assert updated.risk_score == result.risk_score

    def test_scan_nonexistent_device_raises(self, engine: IoTSecurityEngine) -> None:
        with pytest.raises(ValueError, match="not found"):
            engine.scan_device("nonexistent-device-id")

    def test_scan_plc_adds_iec_62443(self, engine: IoTSecurityEngine, plc_device: IoTDevice) -> None:
        result = engine.scan_device(plc_device.id)
        frameworks = {r.framework for r in result.compliance_results}
        assert ComplianceFramework.IEC_62443 in frameworks

    def test_scan_medical_device_adds_fda(self, engine: IoTSecurityEngine, medical_device: IoTDevice) -> None:
        result = engine.scan_device(medical_device.id)
        frameworks = {r.framework for r in result.compliance_results}
        assert ComplianceFramework.FDA_MEDICAL in frameworks

    def test_scan_summary_not_empty(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        result = engine.scan_device(camera_device.id)
        assert len(result.summary) > 0

    def test_scan_with_custom_frameworks(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        result = engine.scan_device(
            camera_device.id,
            frameworks=[ComplianceFramework.NIST_IOT, ComplianceFramework.IEC_62443],
        )
        frameworks = {r.framework for r in result.compliance_results}
        assert ComplianceFramework.NIST_IOT in frameworks
        assert ComplianceFramework.IEC_62443 in frameworks


# ============================================================================
# Summary / stats tests
# ============================================================================


class TestIoTSummary:
    def test_summary_total_devices(self, engine: IoTSecurityEngine,
                                    camera_device: IoTDevice, plc_device: IoTDevice) -> None:
        summary = engine.get_summary("test-org")
        assert summary.total_devices >= 2

    def test_summary_devices_by_type(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        summary = engine.get_summary("test-org")
        assert summary.devices_by_type.get("camera", 0) >= 1

    def test_summary_devices_by_segment(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        summary = engine.get_summary("test-org")
        assert summary.devices_by_segment.get("corporate", 0) >= 1

    def test_summary_different_org_empty(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        summary = engine.get_summary("no-such-org")
        assert summary.total_devices == 0

    def test_summary_counts_segmentation_violations(self, engine: IoTSecurityEngine,
                                                      camera_device: IoTDevice) -> None:
        engine.scan_device(camera_device.id)
        summary = engine.get_summary("test-org")
        assert summary.segmentation_violations >= 1

    def test_summary_counts_eol_firmware(self, engine: IoTSecurityEngine) -> None:
        device = IoTDevice(
            name="EOL Device", device_type=DeviceType.CAMERA, manufacturer="hikvision",
            firmware_version="5.3.0", ip_address="10.0.0.99", org_id="test-org",
        )
        engine.register_device(device)
        engine.analyse_firmware(device)
        summary = engine.get_summary("test-org")
        assert summary.eol_firmware_devices >= 1

    def test_summary_counts_insecure_protocols(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.check_protocols(camera_device)
        summary = engine.get_summary("test-org")
        assert summary.insecure_protocol_devices >= 1

    def test_summary_counts_default_credentials(self, engine: IoTSecurityEngine, camera_device: IoTDevice) -> None:
        engine.check_default_credentials(camera_device)
        summary = engine.get_summary("test-org")
        assert summary.default_credential_devices >= 1

    def test_summary_org_id_matches(self, engine: IoTSecurityEngine) -> None:
        summary = engine.get_summary("test-org")
        assert summary.org_id == "test-org"


# ============================================================================
# Singleton accessor test
# ============================================================================


class TestSingletonAccessor:
    def test_get_iot_engine_returns_same_instance(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, "singleton.db")
            # Reset singleton for test
            import core.iot_security as _mod
            original_engine = _mod._engine
            _mod._engine = None
            try:
                e1 = get_iot_engine(db_path=db)
                e2 = get_iot_engine(db_path=db)
                assert e1 is e2
            finally:
                _mod._engine = original_engine


# ============================================================================
# Router endpoint tests (FastAPI TestClient)
# ============================================================================


class TestIoTRouter:
    @pytest.fixture
    def client(self):
        """Create FastAPI test client with IoT router mounted."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "router_test.db")
            test_engine = IoTSecurityEngine(db_path=db_path)

            from apps.api.iot_security_router import router
            import apps.api.iot_security_router as router_module

            original_engine = router_module._engine
            router_module._engine = test_engine

            app = FastAPI()
            app.include_router(router)
            client = TestClient(app)

            yield client

            router_module._engine = original_engine

    def test_register_device_returns_201(self, client) -> None:
        resp = client.post("/api/v1/iot/devices", json={
            "name": "Test Camera",
            "device_type": "camera",
            "manufacturer": "hikvision",
            "ip_address": "192.168.1.10",
            "org_id": "test-org",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Camera"
        assert "id" in data

    def test_list_devices_returns_200(self, client) -> None:
        client.post("/api/v1/iot/devices", json={
            "name": "Cam A", "device_type": "camera",
            "manufacturer": "hikvision", "ip_address": "10.0.0.1", "org_id": "test-org",
        })
        resp = client.get("/api/v1/iot/devices?org_id=test-org")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_device_returns_200(self, client) -> None:
        create_resp = client.post("/api/v1/iot/devices", json={
            "name": "Cam B", "device_type": "camera",
            "manufacturer": "hikvision", "ip_address": "10.0.0.2", "org_id": "test-org",
        })
        device_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/iot/devices/{device_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == device_id

    def test_get_device_not_found_returns_404(self, client) -> None:
        resp = client.get("/api/v1/iot/devices/does-not-exist")
        assert resp.status_code == 404

    def test_scan_device_returns_scan_result(self, client) -> None:
        create_resp = client.post("/api/v1/iot/devices", json={
            "name": "Scan Cam", "device_type": "camera",
            "manufacturer": "hikvision", "firmware_version": "5.5.0",
            "ip_address": "10.0.0.3", "org_id": "test-org",
            "protocols": ["http", "telnet"],
            "network_segment": "corporate",
        })
        device_id = create_resp.json()["id"]
        resp = client.post(f"/api/v1/iot/devices/{device_id}/scan", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["device_id"] == device_id
        assert "risk_score" in data
        assert "overall_risk" in data

    def test_scan_nonexistent_device_returns_404(self, client) -> None:
        resp = client.post("/api/v1/iot/devices/no-such-device/scan", json={})
        assert resp.status_code == 404

    def test_record_communication_returns_201(self, client) -> None:
        create_resp = client.post("/api/v1/iot/devices", json={
            "name": "Comm Device", "device_type": "sensor",
            "manufacturer": "acme", "ip_address": "10.0.0.4", "org_id": "test-org",
        })
        device_id = create_resp.json()["id"]
        resp = client.post(f"/api/v1/iot/devices/{device_id}/comms", json={
            "remote_ip": "203.0.113.1",
            "remote_port": 443,
            "protocol": "tcp",
            "bytes_sent": 1024,
            "bytes_received": 512,
        })
        assert resp.status_code == 201

    def test_get_comms_anomalies_returns_200(self, client) -> None:
        create_resp = client.post("/api/v1/iot/devices", json={
            "name": "Comms Device", "device_type": "sensor",
            "manufacturer": "acme", "ip_address": "10.0.0.5", "org_id": "test-org",
        })
        device_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/iot/devices/{device_id}/comms")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_compliance_returns_200(self, client) -> None:
        create_resp = client.post("/api/v1/iot/devices", json={
            "name": "Compliance Device", "device_type": "camera",
            "manufacturer": "hikvision", "ip_address": "10.0.0.6", "org_id": "test-org",
        })
        device_id = create_resp.json()["id"]
        # Run a scan to populate compliance data
        client.post(f"/api/v1/iot/devices/{device_id}/scan", json={})
        resp = client.get(f"/api/v1/iot/devices/{device_id}/compliance")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_summary_returns_200(self, client) -> None:
        resp = client.get("/api/v1/iot/summary?org_id=test-org")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_devices" in data
        assert "devices_by_type" in data
        assert "org_id" in data

    def test_list_devices_filter_by_type(self, client) -> None:
        client.post("/api/v1/iot/devices", json={
            "name": "Filter Cam", "device_type": "camera",
            "manufacturer": "hikvision", "ip_address": "10.0.1.1", "org_id": "filter-org",
        })
        client.post("/api/v1/iot/devices", json={
            "name": "Filter PLC", "device_type": "plc",
            "manufacturer": "siemens", "ip_address": "10.0.1.2", "org_id": "filter-org",
        })
        resp = client.get("/api/v1/iot/devices?org_id=filter-org&device_type=camera")
        assert resp.status_code == 200
        devices = resp.json()
        assert all(d["device_type"] == "camera" for d in devices)
