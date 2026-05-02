"""AWS EBS Snapshot Connector — real boto3 adapter for AgentlessSnapshotScanEngine.

Uses ``boto3`` EBS direct API (``GetSnapshotBlock`` / ``ListSnapshotBlocks``) to
stream snapshot block data without mounting a block device.  Falls back to a
no-op credentials-missing result when ``AWS_ACCESS_KEY_ID`` /
``AWS_SECRET_ACCESS_KEY`` are absent and no instance-profile is available.

Credentials resolution order (standard boto3 chain):
1. Explicit constructor kwargs ``aws_access_key_id`` / ``aws_secret_access_key``
2. Environment variables ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` /
   ``AWS_SESSION_TOKEN``
3. Shared credentials file (``~/.aws/credentials``)
4. IAM instance profile / ECS task role / EKS service account

Cross-account support: pass ``role_arn`` to assume an IAM role before listing.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy imports — boto3 is optional; we degrade gracefully without it.
# ---------------------------------------------------------------------------

try:
    import boto3  # type: ignore
    import botocore.exceptions  # type: ignore

    _BOTO3_AVAILABLE = True
except ImportError:  # pragma: no cover
    _BOTO3_AVAILABLE = False


# ---------------------------------------------------------------------------
# Re-export the data types the engine expects so callers only need one import.
# ---------------------------------------------------------------------------

from core.agentless_snapshot_scan_engine import SnapshotBlob, SnapshotRef  # noqa: E402

# ---------------------------------------------------------------------------
# Credential presence check (no SDK call)
# ---------------------------------------------------------------------------


def _aws_credentials_available(
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
) -> bool:
    """Return True if at least one credential source is configured.

    We check the two most common explicit paths.  The full boto3 chain
    (instance role, ECS, EKS, etc.) is satisfied implicitly when boto3 is
    invoked — we don't need to enumerate every source here.
    """
    if aws_access_key_id and aws_secret_access_key:
        return True
    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get(
        "AWS_SECRET_ACCESS_KEY"
    ):
        return True
    # Check shared credentials file.
    creds_file = os.path.expanduser(
        os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")
    )
    if os.path.isfile(creds_file):
        return True
    # Instance metadata / ECS / EKS: we can't check without a network call, so
    # we optimistically return True and let boto3 fail naturally if unavailable.
    if os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
        return True
    if os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE"):
        return True
    return False


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class AWSEBSSnapshotConnector:
    """Real boto3 EBS snapshot adapter.

    Parameters
    ----------
    aws_access_key_id, aws_secret_access_key, aws_session_token:
        Explicit credentials.  If omitted, boto3's default chain is used.
    region_name:
        AWS region (default ``us-east-1``).  Can be overridden per
        ``list_snapshots`` call via the ``account_id`` hint convention
        ``<account>@<region>``.
    role_arn:
        If set, ``STS.assume_role`` is called first (cross-account scanning).
    owner_ids:
        Snapshot owner filter passed to ``describe_snapshots``.  Defaults to
        ``["self"]`` so only snapshots owned by the resolved account are
        returned.
    max_snapshots:
        Safety cap — stop listing after this many snapshots (prevents runaway
        costs on accounts with thousands of snapshots).  Default 500.
    max_block_bytes:
        Maximum bytes to download per snapshot when fetching blocks.  Default
        64 MB — enough to catch secrets/packages in config files near the
        start of the volume.
    """

    def __init__(
        self,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
        region_name: str = "us-east-1",
        role_arn: Optional[str] = None,
        owner_ids: Optional[List[str]] = None,
        max_snapshots: int = 500,
        max_block_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self._key_id = aws_access_key_id or os.environ.get("AWS_ACCESS_KEY_ID")
        self._secret = aws_secret_access_key or os.environ.get(
            "AWS_SECRET_ACCESS_KEY"
        )
        self._token = aws_session_token or os.environ.get("AWS_SESSION_TOKEN")
        self._region = region_name
        self._role_arn = role_arn
        self._owner_ids = owner_ids or ["self"]
        self._max_snapshots = max_snapshots
        self._max_block_bytes = max_block_bytes
        # Session cache: one session per (account, region) pair.
        self._sessions: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _base_session(self) -> Any:
        """Return a boto3 Session using the configured credentials."""
        if not _BOTO3_AVAILABLE:
            raise RuntimeError(
                "boto3 is not installed. "
                "Install it with: pip install boto3"
            )
        kwargs: Dict[str, Any] = {"region_name": self._region}
        if self._key_id:
            kwargs["aws_access_key_id"] = self._key_id
        if self._secret:
            kwargs["aws_secret_access_key"] = self._secret
        if self._token:
            kwargs["aws_session_token"] = self._token
        return boto3.Session(**kwargs)

    def _session_for(self, account_id: str, region: str) -> Any:
        cache_key = f"{account_id}:{region}"
        if cache_key in self._sessions:
            return self._sessions[cache_key]

        base = self._base_session()

        if self._role_arn:
            sts = base.client("sts")
            assumed = sts.assume_role(
                RoleArn=self._role_arn,
                RoleSessionName="aldeci-agentless-scan",
                DurationSeconds=3600,
            )
            creds = assumed["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        else:
            session = boto3.Session(
                aws_access_key_id=self._key_id,
                aws_secret_access_key=self._secret,
                aws_session_token=self._token,
                region_name=region,
            ) if self._key_id else base

        self._sessions[cache_key] = session
        return session

    # ------------------------------------------------------------------
    # SnapshotAdapter protocol
    # ------------------------------------------------------------------

    def list_snapshots(
        self, org_id: str, provider: str, account_id: str
    ) -> List[SnapshotRef]:
        """List EBS snapshots for ``account_id`` via ``ec2.describe_snapshots``.

        Returns ``[]`` with a WARNING log if credentials are absent or the API
        call fails, so the engine records ``status=needs_credentials`` instead
        of crashing.
        """
        if not _aws_credentials_available(self._key_id, self._secret):
            _logger.warning(
                "aws_ebs_connector: no AWS credentials found for org=%s "
                "account=%s — returning empty snapshot list. "
                "Set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY or configure "
                "an IAM role.",
                org_id,
                account_id,
            )
            return []

        # Support account_id@region convention.
        region = self._region
        real_account_id = account_id
        if "@" in account_id:
            real_account_id, region = account_id.split("@", 1)

        try:
            session = self._session_for(real_account_id, region)
            ec2 = session.client("ec2", region_name=region)

            refs: List[SnapshotRef] = []
            paginator = ec2.get_paginator("describe_snapshots")
            page_iter = paginator.paginate(
                OwnerIds=self._owner_ids,
                Filters=[{"Name": "status", "Values": ["completed"]}],
            )
            for page in page_iter:
                for snap in page.get("Snapshots", []):
                    if len(refs) >= self._max_snapshots:
                        _logger.info(
                            "aws_ebs_connector: reached max_snapshots=%d cap for "
                            "org=%s account=%s",
                            self._max_snapshots,
                            org_id,
                            account_id,
                        )
                        return refs
                    tags = {
                        t["Key"]: t["Value"]
                        for t in snap.get("Tags") or []
                    }
                    refs.append(
                        SnapshotRef(
                            snapshot_id=snap["SnapshotId"],
                            provider="aws",
                            account_id=real_account_id,
                            region=snap.get("Region", region),
                            taken_at=snap.get("StartTime", "").isoformat()
                            if hasattr(snap.get("StartTime", ""), "isoformat")
                            else str(snap.get("StartTime", "")),
                            size_gb=snap.get("VolumeSize", 0),
                            tags=tags,
                        )
                    )
            _logger.info(
                "aws_ebs_connector: listed %d snapshots for org=%s account=%s",
                len(refs),
                org_id,
                account_id,
            )
            return refs

        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "aws_ebs_connector: describe_snapshots failed for org=%s "
                "account=%s: %s",
                org_id,
                account_id,
                exc,
            )
            return []

    def fetch_snapshot(self, snapshot_id: str) -> SnapshotBlob:
        """Download up to ``max_block_bytes`` of a snapshot using the EBS
        direct API (``list_snapshot_blocks`` + ``get_snapshot_block``).

        The downloaded blocks are stitched into a single ``__raw_blocks__``
        virtual-file entry in the returned ``SnapshotBlob`` so the engine's
        file-level probes can scan them.  A real production implementation
        would reconstruct the full filesystem via loopback mount or a library
        such as ``dissect.volume``.
        """
        region = self._region
        try:
            session = self._session_for("self", region)
            ebs = session.client("ebs", region_name=region)

            raw_data = bytearray()
            paginator = ebs.get_paginator("list_snapshot_blocks")
            for page in paginator.paginate(SnapshotId=snapshot_id):
                for block in page.get("Blocks", []):
                    if len(raw_data) >= self._max_block_bytes:
                        break
                    block_index = block["BlockIndex"]
                    block_token = block["BlockToken"]
                    resp = ebs.get_snapshot_block(
                        SnapshotId=snapshot_id,
                        BlockIndex=block_index,
                        BlockToken=block_token,
                    )
                    chunk = resp["BlockData"].read()
                    raw_data.extend(chunk)
                    if len(raw_data) >= self._max_block_bytes:
                        break

            _logger.info(
                "aws_ebs_connector: fetched %d bytes from snapshot %s",
                len(raw_data),
                snapshot_id,
            )
            return SnapshotBlob(
                snapshot_id=snapshot_id,
                files={"__raw_blocks__": bytes(raw_data)},
                os_family="linux",
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "aws_ebs_connector: fetch_snapshot failed for %s: %s",
                snapshot_id,
                exc,
            )
            return SnapshotBlob(snapshot_id=snapshot_id, files={}, os_family="unknown")

    def release(self, snapshot_id: str) -> None:
        """No-op for EBS direct API — no persistent streaming session to close."""
        _logger.debug("aws_ebs_connector: released %s", snapshot_id)


__all__ = [
    "AWSEBSSnapshotConnector",
    "_aws_credentials_available",
]
