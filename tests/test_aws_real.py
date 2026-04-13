"""
REAL AWS integration tests against LocalStack.

ALL boto3 calls in this file are REAL HTTP requests to LocalStack at
http://localhost:4566 — no mocks, no patching.

Service availability notes (LocalStack community 3.4):
  - s3, iam, sts   : fully supported in community edition
  - securityhub    : community has BatchImportFindings / BatchUpdateFindings;
                     GetFindings is Pro-only — tests that call it are skipped
                     gracefully when they hit InternalFailure.
  - cloudwatch     : community edition — PutMetricData is supported;
                     GetMetricStatistics may not be fully implemented.

Prerequisites:
    docker compose -f docker/e2e-test-env/docker-compose.e2e.yml up -d localstack

Run:
    pytest tests/test_aws_real.py -v --timeout=60 -m integration

Marks:
    @pytest.mark.integration  — skipped unless LocalStack is reachable
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List

import pytest
import sys

# ---------------------------------------------------------------------------
# Path setup — ensure suite-core is importable
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).parent.parent
_SUITE_CORE = _REPO_ROOT / "suite-core"
if str(_SUITE_CORE) not in sys.path:
    sys.path.insert(0, str(_SUITE_CORE))

from core.aws_integration import (
    ALDECIFinding,
    CloudWatchMetrics,
    IAMAuditor,
    MetricDatum,
    S3EvidenceStore,
    SecurityHubPusher,
)

# ---------------------------------------------------------------------------
# LocalStack endpoint — override via environment variable
# ---------------------------------------------------------------------------
LOCALSTACK_ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
TEST_ORG_ID = f"test-{uuid.uuid4().hex[:8]}"
TEST_ACCOUNT_ID = "000000000000"

# ---------------------------------------------------------------------------
# Mark all tests in this module as integration
# ---------------------------------------------------------------------------
pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# LocalStack health check — skip entire module if not reachable
# ---------------------------------------------------------------------------


def _localstack_is_up() -> bool:
    """Return True if LocalStack is reachable at the configured endpoint."""
    try:
        import urllib.request
        url = f"{LOCALSTACK_ENDPOINT}/_localstack/health"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _localstack_services() -> Dict[str, str]:
    """Fetch the LocalStack health payload and return the services dict."""
    try:
        import urllib.request
        url = f"{LOCALSTACK_ENDPOINT}/_localstack/health"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("services", {})
    except Exception:
        return {}


if not _localstack_is_up():
    pytest.skip(
        f"LocalStack not reachable at {LOCALSTACK_ENDPOINT}. "
        "Start it with: docker compose -f docker/e2e-test-env/docker-compose.e2e.yml up -d localstack",
        allow_module_level=True,
    )

# Cache service availability at collection time
_SERVICES = _localstack_services()
_SECURITYHUB_AVAILABLE = _SERVICES.get("securityhub") in ("running", "available")
_CLOUDWATCH_AVAILABLE = _SERVICES.get("cloudwatch") in ("running", "available")

# Pytest skip markers for Pro-only services
requires_securityhub = pytest.mark.skipif(
    not _SECURITYHUB_AVAILABLE,
    reason="SecurityHub not available in LocalStack community edition at this endpoint",
)
requires_cloudwatch = pytest.mark.skipif(
    not _CLOUDWATCH_AVAILABLE,
    reason="CloudWatch not available in LocalStack community edition at this endpoint",
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def s3_store() -> Generator[S3EvidenceStore, None, None]:
    """Create an S3EvidenceStore for the test org and clean up after all tests."""
    store = S3EvidenceStore(
        org_id=TEST_ORG_ID,
        endpoint_url=LOCALSTACK_ENDPOINT,
        region=AWS_REGION,
    )
    store.ensure_bucket()
    yield store
    # Teardown: remove bucket and all objects
    try:
        store.delete_bucket()
    except Exception:
        pass


@pytest.fixture(scope="module")
def sh_pusher() -> Generator[SecurityHubPusher, None, None]:
    """Create a SecurityHubPusher and enable Security Hub once."""
    pusher = SecurityHubPusher(
        account_id=TEST_ACCOUNT_ID,
        region=AWS_REGION,
        endpoint_url=LOCALSTACK_ENDPOINT,
    )
    try:
        pusher.enable_security_hub()
    except Exception:
        pass  # May already be enabled or unavailable
    yield pusher


@pytest.fixture(scope="module")
def iam_auditor() -> IAMAuditor:
    return IAMAuditor(endpoint_url=LOCALSTACK_ENDPOINT, region=AWS_REGION)


@pytest.fixture(scope="module")
def cw_metrics() -> CloudWatchMetrics:
    return CloudWatchMetrics(
        endpoint_url=LOCALSTACK_ENDPOINT,
        region=AWS_REGION,
        org_id=TEST_ORG_ID,
    )


# ---------------------------------------------------------------------------
# Helper — build a sample ALDECIFinding
# ---------------------------------------------------------------------------


def _make_finding(
    severity: str = "high",
    title: str = "Test Finding",
    resource_id: str = "i-test-001",
) -> ALDECIFinding:
    return ALDECIFinding(
        finding_id=f"aldeci-test-{uuid.uuid4()}",
        title=title,
        description=f"Test description for {title}",
        severity=severity,
        resource_id=resource_id,
        resource_type="AwsEc2Instance",
        generator_id="aldeci-test-scanner",
        account_id=TEST_ACCOUNT_ID,
        region=AWS_REGION,
        remediation_text="Apply the security patch.",
        remediation_url="https://aldeci.example.com/remediation",
    )


# ===========================================================================
# S3 Evidence Store Tests  (all run against community LocalStack)
# ===========================================================================


class TestS3EvidenceStore:
    """Real S3 API calls against LocalStack — all pass on community edition."""

    def test_bucket_exists_after_ensure(self, s3_store: S3EvidenceStore) -> None:
        """Bucket should exist (created in fixture)."""
        import boto3
        client = boto3.client(
            "s3",
            endpoint_url=LOCALSTACK_ENDPOINT,
            region_name=AWS_REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        response = client.head_bucket(Bucket=s3_store.bucket)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_ensure_bucket_idempotent(self, s3_store: S3EvidenceStore) -> None:
        """Calling ensure_bucket() twice should not raise and return False."""
        result = s3_store.ensure_bucket()
        assert result is False

    def test_upload_scan_report_returns_key(self, s3_store: S3EvidenceStore) -> None:
        """Upload a scan report and verify the returned key and etag."""
        payload = json.dumps({"scanner": "trivy", "cves": ["CVE-2021-44228"]}).encode()
        result = s3_store.upload_scan_report("trivy", payload, metadata={"target": "webgoat"})

        assert result.bucket == s3_store.bucket
        assert "reports/trivy/" in result.key
        assert result.etag != ""

    def test_upload_scan_report_verifiable_in_list(self, s3_store: S3EvidenceStore) -> None:
        """Uploaded report must appear in list_objects."""
        payload = b'{"scanner": "semgrep", "findings": 5}'
        result = s3_store.upload_scan_report("semgrep", payload)

        objects = s3_store.list_objects(prefix="reports/semgrep/")
        keys = [o["key"] for o in objects]
        assert result.key in keys

    def test_upload_sbom_cyclonedx(self, s3_store: S3EvidenceStore) -> None:
        """Upload a CycloneDX SBOM and verify it appears in the sboms/ prefix."""
        sbom = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [{"type": "library", "name": "log4j", "version": "2.14.1"}],
        }).encode()
        result = s3_store.upload_sbom("webgoat-app", sbom, format="cyclonedx")

        assert "sboms/webgoat-app/" in result.key
        objects = s3_store.list_objects(prefix="sboms/webgoat-app/")
        keys = [o["key"] for o in objects]
        assert result.key in keys

    def test_upload_compliance_evidence_pdf(self, s3_store: S3EvidenceStore) -> None:
        """Upload fake compliance evidence and verify prefix."""
        fake_pdf = b"%PDF-1.4 fake compliance evidence"
        result = s3_store.upload_compliance_evidence(
            framework="soc2",
            control_id="CC7.2",
            content=fake_pdf,
            content_type="application/pdf",
            metadata={"auditor": "internal", "period": "2026-Q1"},
        )

        assert "compliance/soc2/CC7.2/" in result.key
        objects = s3_store.list_objects(prefix="compliance/soc2/")
        keys = [o["key"] for o in objects]
        assert result.key in keys

    def test_list_objects_empty_prefix(self, s3_store: S3EvidenceStore) -> None:
        """list_objects with no prefix returns all uploaded objects."""
        objects = s3_store.list_objects()
        assert isinstance(objects, list)
        assert len(objects) >= 3

    def test_list_objects_contains_size(self, s3_store: S3EvidenceStore) -> None:
        """Each listed object should have a size field."""
        objects = s3_store.list_objects()
        for obj in objects:
            assert "size" in obj
            assert obj["size"] >= 0

    def test_list_objects_contains_etag(self, s3_store: S3EvidenceStore) -> None:
        """Each listed object should have an etag field."""
        objects = s3_store.list_objects()
        for obj in objects:
            assert "etag" in obj

    def test_presigned_url_generated(self, s3_store: S3EvidenceStore) -> None:
        """Presigned URL should be a non-empty string containing bucket name or endpoint."""
        payload = b'{"test": "presigned"}'
        result = s3_store.upload_scan_report("trivy", payload, filename="presign-test.json")
        url = s3_store.generate_presigned_url(result.key, expiry_seconds=300)

        assert isinstance(url, str)
        assert len(url) > 0
        assert s3_store.bucket in url or "localhost" in url

    def test_presigned_url_is_downloadable(self, s3_store: S3EvidenceStore) -> None:
        """Presigned URL should return the uploaded content when fetched."""
        content = b'{"presigned": "downloadable", "value": 42}'
        result = s3_store.upload_scan_report("trivy", content, filename="dl-test.json")
        url = s3_store.generate_presigned_url(result.key)

        import urllib.request
        with urllib.request.urlopen(url, timeout=10) as resp:
            body = resp.read()
        assert body == content

    def test_delete_object(self, s3_store: S3EvidenceStore) -> None:
        """Deleted object should no longer appear in listing."""
        payload = b'{"ephemeral": true}'
        result = s3_store.upload_scan_report("trivy", payload, filename="delete-me.json")

        objects_before = s3_store.list_objects(prefix=result.key)
        assert any(o["key"] == result.key for o in objects_before)

        s3_store.delete_object(result.key)
        objects_after = s3_store.list_objects(prefix=result.key)
        assert not any(o["key"] == result.key for o in objects_after)

    def test_upload_with_server_side_encryption_header(self, s3_store: S3EvidenceStore) -> None:
        """Verify that a PUT with SSE AES256 succeeds against LocalStack."""
        import boto3
        client = boto3.client(
            "s3",
            endpoint_url=LOCALSTACK_ENDPOINT,
            region_name=AWS_REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        payload = b'{"sse": "aes256"}'
        key = f"test/sse-{uuid.uuid4()}.json"
        resp = client.put_object(
            Bucket=s3_store.bucket,
            Key=key,
            Body=payload,
            ServerSideEncryption="AES256",
        )
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        client.delete_object(Bucket=s3_store.bucket, Key=key)

    def test_multiple_scan_reports_different_scanners(self, s3_store: S3EvidenceStore) -> None:
        """Upload reports from three different scanners and verify all are stored."""
        scanners = ["trivy", "snyk", "grype"]
        keys: List[str] = []
        for scanner in scanners:
            result = s3_store.upload_scan_report(scanner, f'{{"scanner":"{scanner}"}}'.encode())
            keys.append(result.key)

        all_objects = s3_store.list_objects()
        all_keys = {o["key"] for o in all_objects}
        for key in keys:
            assert key in all_keys, f"Key {key} not found in S3"


# ===========================================================================
# Security Hub Tests
# ===========================================================================


class TestSecurityHubPusher:
    """
    Real SecurityHub API calls against LocalStack.

    ASFF conversion and push_findings batching logic tests run unconditionally
    (they verify the integration code, not the remote service).

    Tests that require the remote service respond (BatchImportFindings) are
    guarded by ``requires_securityhub``; those that call GetFindings (Pro-only
    even when the service is "available") catch InternalFailure gracefully.
    """

    # ------------------------------------------------------------------
    # ASFF conversion — no remote call, always run
    # ------------------------------------------------------------------

    def test_asff_structure_valid(self, sh_pusher: SecurityHubPusher) -> None:
        """_to_asff must produce all mandatory ASFF fields."""
        finding = _make_finding(severity="high")
        asff = sh_pusher._to_asff(finding)

        required_fields = [
            "SchemaVersion", "Id", "ProductArn", "GeneratorId",
            "AwsAccountId", "Types", "CreatedAt", "UpdatedAt",
            "Severity", "Title", "Description", "Resources",
        ]
        for field_name in required_fields:
            assert field_name in asff, f"Missing ASFF field: {field_name}"

    def test_asff_severity_critical_maps_correctly(self, sh_pusher: SecurityHubPusher) -> None:
        """CRITICAL severity → Label=CRITICAL, Normalized=90."""
        asff = sh_pusher._to_asff(_make_finding(severity="critical"))
        assert asff["Severity"]["Label"] == "CRITICAL"
        assert asff["Severity"]["Normalized"] == 90

    def test_asff_severity_high_maps_correctly(self, sh_pusher: SecurityHubPusher) -> None:
        """HIGH severity → Label=HIGH, Normalized=70."""
        asff = sh_pusher._to_asff(_make_finding(severity="high"))
        assert asff["Severity"]["Label"] == "HIGH"
        assert asff["Severity"]["Normalized"] == 70

    def test_asff_severity_medium_maps_correctly(self, sh_pusher: SecurityHubPusher) -> None:
        """MEDIUM severity → Label=MEDIUM, Normalized=50."""
        asff = sh_pusher._to_asff(_make_finding(severity="medium"))
        assert asff["Severity"]["Label"] == "MEDIUM"
        assert asff["Severity"]["Normalized"] == 50

    def test_asff_severity_low_maps_correctly(self, sh_pusher: SecurityHubPusher) -> None:
        """LOW severity → Label=LOW, Normalized=25."""
        asff = sh_pusher._to_asff(_make_finding(severity="low"))
        assert asff["Severity"]["Label"] == "LOW"
        assert asff["Severity"]["Normalized"] == 25

    def test_asff_severity_info_maps_correctly(self, sh_pusher: SecurityHubPusher) -> None:
        """INFO severity → Label=INFORMATIONAL, Normalized=0."""
        asff = sh_pusher._to_asff(_make_finding(severity="info"))
        assert asff["Severity"]["Label"] == "INFORMATIONAL"
        assert asff["Severity"]["Normalized"] == 0

    def test_asff_remediation_included(self, sh_pusher: SecurityHubPusher) -> None:
        """Finding with remediation text should include Remediation key in ASFF."""
        finding = _make_finding(severity="high")
        asff = sh_pusher._to_asff(finding)
        assert "Remediation" in asff
        assert asff["Remediation"]["Recommendation"]["Text"] == "Apply the security patch."

    def test_asff_resource_fields(self, sh_pusher: SecurityHubPusher) -> None:
        """Resources list should contain Type, Id, Partition, Region."""
        finding = _make_finding(severity="medium", resource_id="arn:aws:s3:::my-bucket")
        asff = sh_pusher._to_asff(finding)
        resource = asff["Resources"][0]
        assert resource["Type"] == "AwsEc2Instance"
        assert resource["Id"] == "arn:aws:s3:::my-bucket"
        assert resource["Partition"] == "aws"
        assert resource["Region"] == AWS_REGION

    def test_push_empty_list_returns_zero(self, sh_pusher: SecurityHubPusher) -> None:
        """Pushing an empty list must return zeros without any API call."""
        result = sh_pusher.push_findings([])
        assert result.success_count == 0
        assert result.failed_count == 0

    # ------------------------------------------------------------------
    # Real HTTP calls to SecurityHub — skip if not available
    # ------------------------------------------------------------------

    @requires_securityhub
    def test_push_single_high_finding(self, sh_pusher: SecurityHubPusher) -> None:
        """Push a single HIGH finding and verify SuccessCount == 1."""
        result = sh_pusher.push_findings([_make_finding(severity="high", title="High severity CVE test")])
        assert result.success_count == 1
        assert result.failed_count == 0

    @requires_securityhub
    def test_push_single_critical_finding(self, sh_pusher: SecurityHubPusher) -> None:
        """Push a CRITICAL finding."""
        result = sh_pusher.push_findings([_make_finding(severity="critical", title="Log4Shell RCE detected")])
        assert result.success_count == 1
        assert result.failed_count == 0

    @requires_securityhub
    def test_push_multiple_severity_levels(self, sh_pusher: SecurityHubPusher) -> None:
        """Push findings for all five severity levels in one batch."""
        findings = [
            _make_finding(severity=sev, title=f"{sev.capitalize()} test finding")
            for sev in ["critical", "high", "medium", "low", "info"]
        ]
        result = sh_pusher.push_findings(findings)
        assert result.success_count == 5
        assert result.failed_count == 0

    @requires_securityhub
    def test_push_batch_over_100_findings(self, sh_pusher: SecurityHubPusher) -> None:
        """Pushing 110 findings should auto-batch into two API calls (100 + 10)."""
        findings = [
            _make_finding(severity="low", title=f"Batch test {i}", resource_id=f"i-batch-{i:04d}")
            for i in range(110)
        ]
        result = sh_pusher.push_findings(findings)
        assert result.success_count == 110
        assert result.failed_count == 0

    @requires_securityhub
    def test_push_finding_with_remediation(self, sh_pusher: SecurityHubPusher) -> None:
        """Finding with remediation URL must push without error."""
        finding = ALDECIFinding(
            finding_id=f"aldeci-rem-{uuid.uuid4()}",
            title="Remediation test finding",
            description="Needs patching.",
            severity="high",
            resource_id="arn:aws:s3:::my-bucket",
            resource_type="AwsS3Bucket",
            remediation_text="Enable S3 Block Public Access.",
            remediation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            account_id=TEST_ACCOUNT_ID,
            region=AWS_REGION,
        )
        result = sh_pusher.push_findings([finding])
        assert result.success_count == 1

    def test_get_findings_real_call(self, sh_pusher: SecurityHubPusher) -> None:
        """
        get_findings makes a real HTTP call to LocalStack.

        On community LocalStack, GetFindings returns InternalFailure (Pro-only);
        we verify the integration code actually fires the HTTP request and either:
        - returns a list (if available), or
        - raises ClientError with a known message (not implemented).
        """
        import botocore.exceptions
        try:
            findings = sh_pusher.get_findings(max_results=5)
            assert isinstance(findings, list)
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            # Acceptable: service not implemented in community
            assert error_code in ("InternalFailure", "InvalidClientTokenId", "AccessDeniedException"), \
                f"Unexpected ClientError: {exc}"


# ===========================================================================
# IAM Auditor Tests  (all run against community LocalStack)
# ===========================================================================


class TestIAMAuditor:
    """Real IAM API calls against LocalStack — all pass on community edition."""

    @pytest.fixture(autouse=True)
    def _create_test_users(self, iam_auditor: IAMAuditor) -> Generator[None, None, None]:
        """Create test IAM users and access keys; delete them after each test."""
        import boto3
        client = boto3.client(
            "iam",
            endpoint_url=LOCALSTACK_ENDPOINT,
            region_name=AWS_REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        self._test_usernames = [f"aldeci-test-user-{uuid.uuid4().hex[:6]}" for _ in range(3)]

        for username in self._test_usernames:
            try:
                client.create_user(UserName=username)
                client.create_access_key(UserName=username)
            except Exception:
                pass

        yield

        for username in self._test_usernames:
            try:
                keys = client.list_access_keys(UserName=username)
                for k in keys.get("AccessKeyMetadata", []):
                    client.delete_access_key(UserName=username, AccessKeyId=k["AccessKeyId"])
                client.delete_user(UserName=username)
            except Exception:
                pass

    def test_list_users_returns_list(self, iam_auditor: IAMAuditor) -> None:
        """list_users_with_access_keys should return a list with at least our 3 test users."""
        users = iam_auditor.list_users_with_access_keys()
        assert isinstance(users, list)
        assert len(users) >= 3

    def test_list_users_have_expected_fields(self, iam_auditor: IAMAuditor) -> None:
        """Each user entry should have username, user_id, arn, access_keys."""
        users = iam_auditor.list_users_with_access_keys()
        for user in users:
            assert "username" in user
            assert "user_id" in user
            assert "arn" in user
            assert "access_keys" in user
            assert isinstance(user["access_keys"], list)

    def test_test_users_have_access_keys(self, iam_auditor: IAMAuditor) -> None:
        """Newly created test users should each have exactly one access key."""
        users = iam_auditor.list_users_with_access_keys()
        test_users = {u["username"]: u for u in users if u["username"] in self._test_usernames}
        assert len(test_users) == 3
        for username, user in test_users.items():
            assert len(user["access_keys"]) >= 1, f"{username} should have at least one key"

    def test_check_mfa_enforcement_returns_dict(self, iam_auditor: IAMAuditor) -> None:
        """check_mfa_enforcement should return a dict mapping username to bool."""
        mfa = iam_auditor.check_mfa_enforcement()
        assert isinstance(mfa, dict)

    def test_test_users_have_no_mfa(self, iam_auditor: IAMAuditor) -> None:
        """Freshly created users have no MFA devices enrolled."""
        mfa = iam_auditor.check_mfa_enforcement()
        for username in self._test_usernames:
            if username in mfa:
                assert mfa[username] is False, f"{username} should have MFA disabled"

    def test_detect_overprivileged_returns_list(self, iam_auditor: IAMAuditor) -> None:
        """detect_overprivileged_policies should return a list."""
        result = iam_auditor.detect_overprivileged_policies()
        assert isinstance(result, list)

    def test_full_audit_returns_summary(self, iam_auditor: IAMAuditor) -> None:
        """full_audit should return an IAMAuditSummary with correct shape."""
        summary = iam_auditor.full_audit()
        assert summary.total_users >= 3
        assert isinstance(summary.users_without_mfa, int)
        assert isinstance(summary.users_with_old_keys, int)
        assert isinstance(summary.user_details, list)
        assert len(summary.user_details) >= 3

    def test_full_audit_risk_flags_no_mfa(self, iam_auditor: IAMAuditor) -> None:
        """Test users should have 'no_mfa' in risk_flags."""
        summary = iam_auditor.full_audit()
        test_user_details = [
            u for u in summary.user_details if u.username in self._test_usernames
        ]
        assert len(test_user_details) == 3
        for user in test_user_details:
            assert "no_mfa" in user.risk_flags, f"{user.username} should have no_mfa flag"

    def test_full_audit_timestamp_is_utc_string(self, iam_auditor: IAMAuditor) -> None:
        """Audit summary timestamp should be a valid ISO8601 string."""
        summary = iam_auditor.full_audit()
        assert isinstance(summary.audit_timestamp, str)
        assert len(summary.audit_timestamp) > 10


# ===========================================================================
# CloudWatch Metrics Tests
# ===========================================================================


class TestCloudWatchMetrics:
    """
    Real CloudWatch API calls against LocalStack.

    PutMetricData is available in community LocalStack when ``cloudwatch``
    is in the SERVICES list. Tests are guarded by ``requires_cloudwatch``.
    GetMetricStatistics is tested with a graceful fallback for
    not-yet-implemented variants.
    """

    @requires_cloudwatch
    def test_push_finding_counts_by_severity(self, cw_metrics: CloudWatchMetrics) -> None:
        """Push finding counts for all severity levels."""
        counts = {"critical": 3, "high": 12, "medium": 45, "low": 8, "info": 2}
        pushed = cw_metrics.push_finding_counts(counts)
        assert pushed == len(counts)

    @requires_cloudwatch
    def test_push_scan_duration_trivy(self, cw_metrics: CloudWatchMetrics) -> None:
        """Push scan duration for the trivy scanner."""
        pushed = cw_metrics.push_scan_duration("trivy", 47.3)
        assert pushed == 1

    @requires_cloudwatch
    def test_push_scan_duration_semgrep(self, cw_metrics: CloudWatchMetrics) -> None:
        """Push scan duration for semgrep."""
        pushed = cw_metrics.push_scan_duration("semgrep", 120.8)
        assert pushed == 1

    @requires_cloudwatch
    def test_push_risk_score(self, cw_metrics: CloudWatchMetrics) -> None:
        """Push a risk score (0-100) for an application."""
        pushed = cw_metrics.push_risk_score("webgoat-app", 87.5)
        assert pushed == 1

    @requires_cloudwatch
    def test_push_council_consensus_rate(self, cw_metrics: CloudWatchMetrics) -> None:
        """Push LLM Council consensus rate (0.0-1.0 converted to percent)."""
        pushed = cw_metrics.push_council_consensus_rate(0.92)
        assert pushed == 1

    @requires_cloudwatch
    def test_put_metrics_single(self, cw_metrics: CloudWatchMetrics) -> None:
        """put_metrics with one MetricDatum should return 1."""
        metrics = [
            MetricDatum(
                name="TestMetric",
                value=42.0,
                unit="Count",
                dimensions={"TestDim": "unit-test"},
            )
        ]
        pushed = cw_metrics.put_metrics(metrics)
        assert pushed == 1

    @requires_cloudwatch
    def test_put_metrics_batch_over_20(self, cw_metrics: CloudWatchMetrics) -> None:
        """put_metrics with 25 items should batch into two calls and return 25."""
        metrics = [
            MetricDatum(
                name="BatchMetric",
                value=float(i),
                unit="Count",
                dimensions={"Index": str(i)},
            )
            for i in range(25)
        ]
        pushed = cw_metrics.put_metrics(metrics)
        assert pushed == 25

    @requires_cloudwatch
    def test_push_zero_value_metric(self, cw_metrics: CloudWatchMetrics) -> None:
        """Pushing a metric with value 0 should succeed."""
        pushed = cw_metrics.push_finding_counts({"critical": 0, "high": 0})
        assert pushed == 2

    @requires_cloudwatch
    def test_push_fractional_risk_score(self, cw_metrics: CloudWatchMetrics) -> None:
        """Risk score can be a float between 0 and 100."""
        pushed = cw_metrics.push_risk_score("juiceshop", 23.456)
        assert pushed == 1

    def test_get_metric_statistics_real_call(self, cw_metrics: CloudWatchMetrics) -> None:
        """
        get_metric_statistics makes a real HTTP call.

        On community LocalStack without cloudwatch, it raises ClientError;
        we accept either a list result or a known not-implemented error.
        """
        import botocore.exceptions
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=1)
        try:
            datapoints = cw_metrics.get_metric_statistics(
                metric_name="FindingCount",
                start_time=start,
                end_time=end,
                period_seconds=3600,
                stat="Sum",
                dimensions={"Severity": "CRITICAL", "OrgId": TEST_ORG_ID},
            )
            assert isinstance(datapoints, list)
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            # Accept any server-side error indicating the service/operation is
            # not available in this LocalStack edition or configuration.
            acceptable = (
                "InternalFailure", "InternalError", "InvalidClientTokenId",
                "ServiceUnavailableException", "500",
            )
            assert error_code in acceptable, f"Unexpected ClientError: {exc}"


# ===========================================================================
# Cross-service integration tests
# ===========================================================================


class TestCrossServiceIntegration:
    """End-to-end tests combining S3, SecurityHub, IAM, and CloudWatch."""

    def test_scan_report_upload_and_s3_listing(
        self,
        s3_store: S3EvidenceStore,
    ) -> None:
        """
        Upload a scan report then verify it appears in S3 listing.
        Pure S3 — runs on community LocalStack.
        """
        report = json.dumps({
            "scanner": "trivy",
            "target": "webgoat:latest",
            "cves": [{"id": "CVE-2021-44228", "severity": "CRITICAL"}],
        }).encode()
        upload_result = s3_store.upload_scan_report(
            "trivy",
            report,
            metadata={"target": "webgoat:latest", "org": TEST_ORG_ID},
        )
        assert upload_result.etag != ""

        objects = s3_store.list_objects(prefix="reports/trivy/")
        assert any(upload_result.key == o["key"] for o in objects)

    def test_compliance_evidence_full_flow(
        self,
        s3_store: S3EvidenceStore,
    ) -> None:
        """Upload compliance evidence for three frameworks and verify all in S3."""
        frameworks = [
            ("soc2", "CC6.1"),
            ("pci-dss", "REQ-6.3"),
            ("nist-csf", "ID.AM-1"),
        ]
        uploaded_keys: List[str] = []
        for framework, control in frameworks:
            evidence = json.dumps({
                "framework": framework,
                "control": control,
                "status": "compliant",
                "evidence_date": datetime.now(timezone.utc).isoformat(),
            }).encode()
            result = s3_store.upload_compliance_evidence(
                framework=framework,
                control_id=control,
                content=evidence,
                content_type="application/json",
            )
            uploaded_keys.append(result.key)

        all_objects = s3_store.list_objects(prefix="compliance/")
        all_keys = {o["key"] for o in all_objects}
        for key in uploaded_keys:
            assert key in all_keys, f"Compliance evidence key {key} not found in S3"

    @requires_securityhub
    def test_scan_report_upload_and_finding_push(
        self,
        s3_store: S3EvidenceStore,
        sh_pusher: SecurityHubPusher,
    ) -> None:
        """
        Full pipeline: upload scan report to S3, push finding to SecurityHub.
        Requires SecurityHub to be available (community or Pro LocalStack).
        """
        report = json.dumps({"scanner": "trivy", "cves": [{"id": "CVE-2021-44228"}]}).encode()
        upload_result = s3_store.upload_scan_report("trivy", report)
        assert upload_result.etag != ""

        finding = ALDECIFinding(
            finding_id=f"e2e-{uuid.uuid4()}",
            title="CVE-2021-44228 Log4Shell in webgoat:latest",
            description="Apache Log4j 2 RCE via JNDI lookup",
            severity="critical",
            resource_id="webgoat:latest",
            resource_type="AwsEcrContainerImage",
            generator_id="aldeci-trivy-scanner",
            account_id=TEST_ACCOUNT_ID,
            region=AWS_REGION,
        )
        push_result = sh_pusher.push_findings([finding])
        assert push_result.success_count == 1
