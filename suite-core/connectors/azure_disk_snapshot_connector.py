"""Azure Managed Disk Snapshot Connector — real azure-mgmt-compute adapter.

Uses ``azure-mgmt-compute`` ``SnapshotsOperations.list()`` to enumerate
managed-disk snapshots and ``begin_grant_access()`` to obtain a time-limited
SAS download URL.  The raw bytes are downloaded via ``urllib`` (no extra dep).

Credentials resolution order:
1. Explicit constructor kwargs ``client_id`` / ``client_secret`` / ``tenant_id``
2. Environment variables ``AZURE_CLIENT_ID`` / ``AZURE_CLIENT_SECRET`` /
   ``AZURE_TENANT_ID`` + ``AZURE_SUBSCRIPTION_ID``
3. ``DefaultAzureCredential`` (managed identity, CLI, env, workload identity)

Falls back to an empty list with a WARNING when credentials are absent so the
engine records ``status=needs_credentials`` instead of crashing.
"""

from __future__ import annotations

import io
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy imports — azure SDK is optional.
# ---------------------------------------------------------------------------

try:
    from azure.identity import (  # type: ignore
        ClientSecretCredential,
        DefaultAzureCredential,
    )
    from azure.mgmt.compute import ComputeManagementClient  # type: ignore

    _AZURE_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _AZURE_SDK_AVAILABLE = False

from core.agentless_snapshot_scan_engine import SnapshotBlob, SnapshotRef  # noqa: E402

# ---------------------------------------------------------------------------
# Credential presence check (no SDK call)
# ---------------------------------------------------------------------------


def _azure_credentials_available(
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> bool:
    """Return True if service-principal or managed-identity creds are present."""
    resolved_id = client_id or os.environ.get("AZURE_CLIENT_ID")
    resolved_secret = client_secret or os.environ.get("AZURE_CLIENT_SECRET")
    resolved_tenant = tenant_id or os.environ.get("AZURE_TENANT_ID")
    if resolved_id and resolved_secret and resolved_tenant:
        return True
    # Managed identity (IMDS) — MSI_ENDPOINT or IDENTITY_ENDPOINT signals it.
    if os.environ.get("MSI_ENDPOINT") or os.environ.get("IDENTITY_ENDPOINT"):
        return True
    # Azure CLI token cache.
    azure_cli_dir = os.path.expanduser("~/.azure/accessTokens.json")
    if os.path.isfile(azure_cli_dir):
        return True
    return False


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class AzureDiskSnapshotConnector:
    """Real azure-mgmt-compute snapshot adapter.

    Parameters
    ----------
    subscription_id:
        Azure subscription to scan.  Falls back to ``AZURE_SUBSCRIPTION_ID``
        env var.
    client_id, client_secret, tenant_id:
        Service-principal credentials.  If omitted, ``DefaultAzureCredential``
        is used (managed identity, CLI login, etc.).
    resource_group:
        If set, list snapshots only from this resource group.  Otherwise all
        resource groups in the subscription are scanned.
    max_snapshots:
        Safety cap to prevent runaway API calls.  Default 500.
    sas_access_duration_seconds:
        Duration of the SAS URI granted for snapshot download.  Default 3600.
    max_download_bytes:
        Maximum bytes to download from the SAS URI.  Default 64 MB.
    """

    def __init__(
        self,
        subscription_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        tenant_id: Optional[str] = None,
        resource_group: Optional[str] = None,
        max_snapshots: int = 500,
        sas_access_duration_seconds: int = 3600,
        max_download_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self._subscription_id = subscription_id or os.environ.get(
            "AZURE_SUBSCRIPTION_ID", ""
        )
        self._client_id = client_id or os.environ.get("AZURE_CLIENT_ID")
        self._client_secret = client_secret or os.environ.get("AZURE_CLIENT_SECRET")
        self._tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID")
        self._resource_group = resource_group
        self._max_snapshots = max_snapshots
        self._sas_duration = sas_access_duration_seconds
        self._max_download_bytes = max_download_bytes
        # Lazily constructed compute client.
        self._compute_client: Optional[Any] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _credential(self) -> Any:
        if not _AZURE_SDK_AVAILABLE:
            raise RuntimeError(
                "azure-mgmt-compute and azure-identity are not installed. "
                "Install with: pip install azure-mgmt-compute azure-identity"
            )
        if self._client_id and self._client_secret and self._tenant_id:
            return ClientSecretCredential(
                tenant_id=self._tenant_id,
                client_id=self._client_id,
                client_secret=self._client_secret,
            )
        return DefaultAzureCredential()

    def _client(self) -> Any:
        if self._compute_client is None:
            if not self._subscription_id:
                raise ValueError(
                    "Azure subscription_id is required. Set AZURE_SUBSCRIPTION_ID "
                    "or pass subscription_id to AzureDiskSnapshotConnector()."
                )
            self._compute_client = ComputeManagementClient(
                credential=self._credential(),
                subscription_id=self._subscription_id,
            )
        return self._compute_client

    # ------------------------------------------------------------------
    # SnapshotAdapter protocol
    # ------------------------------------------------------------------

    def list_snapshots(
        self, org_id: str, provider: str, account_id: str
    ) -> List[SnapshotRef]:
        """List Azure managed-disk snapshots.

        ``account_id`` is treated as the Azure subscription ID if it differs
        from the constructor value (allows per-call subscription override).

        Returns ``[]`` with a WARNING when credentials or the subscription ID
        are absent.
        """
        if not _azure_credentials_available(
            self._client_id, self._client_secret, self._tenant_id
        ):
            _logger.warning(
                "azure_disk_connector: no Azure credentials found for org=%s "
                "account=%s — returning empty snapshot list. "
                "Set AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID "
                "or configure a managed identity.",
                org_id,
                account_id,
            )
            return []

        if not self._subscription_id and not account_id:
            _logger.warning(
                "azure_disk_connector: no subscription_id for org=%s — "
                "returning empty list.",
                org_id,
            )
            return []

        try:
            client = self._client()
            refs: List[SnapshotRef] = []

            if self._resource_group:
                iterator = client.snapshots.list_by_resource_group(
                    self._resource_group
                )
            else:
                iterator = client.snapshots.list()

            for snap in iterator:
                if len(refs) >= self._max_snapshots:
                    _logger.info(
                        "azure_disk_connector: reached max_snapshots=%d cap for "
                        "org=%s account=%s",
                        self._max_snapshots,
                        org_id,
                        account_id,
                    )
                    break

                # Parse resource-group name from the resource ID.
                snap_id: str = snap.id or ""
                rg = ""
                parts = snap_id.split("/")
                if "resourceGroups" in parts:
                    rg_idx = parts.index("resourceGroups")
                    if rg_idx + 1 < len(parts):
                        rg = parts[rg_idx + 1]

                taken_at = ""
                if snap.time_created:
                    taken_at = snap.time_created.isoformat()

                tags: Dict[str, str] = {}
                if snap.tags:
                    tags = {k: str(v) for k, v in snap.tags.items()}
                tags["resource_group"] = rg

                refs.append(
                    SnapshotRef(
                        snapshot_id=snap.name or snap_id,
                        provider="azure",
                        account_id=self._subscription_id or account_id,
                        region=snap.location or "",
                        taken_at=taken_at,
                        size_gb=snap.disk_size_gb or 0,
                        tags=tags,
                    )
                )

            _logger.info(
                "azure_disk_connector: listed %d snapshots for org=%s account=%s",
                len(refs),
                org_id,
                account_id,
            )
            return refs

        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "azure_disk_connector: list_snapshots failed for org=%s "
                "account=%s: %s",
                org_id,
                account_id,
                exc,
            )
            return []

    def fetch_snapshot(self, snapshot_id: str) -> SnapshotBlob:
        """Grant read-access to a managed-disk snapshot and download its bytes.

        Uses ``snapshots.begin_grant_access()`` to get a SAS URI, then
        downloads up to ``max_download_bytes`` bytes via an HTTP GET.

        The raw bytes are placed in a ``__raw_disk__`` virtual file in the
        returned ``SnapshotBlob``.
        """
        resource_group = self._resource_group or ""
        if not resource_group:
            _logger.warning(
                "azure_disk_connector: resource_group not set, cannot fetch "
                "snapshot %s — returning empty blob.",
                snapshot_id,
            )
            return SnapshotBlob(snapshot_id=snapshot_id, files={}, os_family="unknown")

        try:
            client = self._client()
            poller = client.snapshots.begin_grant_access(
                resource_group_name=resource_group,
                snapshot_name=snapshot_id,
                grant_access_data={
                    "access": "Read",
                    "durationInSeconds": self._sas_duration,
                },
            )
            access_uri_obj = poller.result()
            sas_url: str = (
                access_uri_obj.access_sas
                if hasattr(access_uri_obj, "access_sas")
                else str(access_uri_obj)
            )

            _logger.info(
                "azure_disk_connector: obtained SAS URI for snapshot %s, "
                "downloading up to %d bytes",
                snapshot_id,
                self._max_download_bytes,
            )

            buf = io.BytesIO()
            req = urllib.request.Request(sas_url)
            req.add_header("Range", f"bytes=0-{self._max_download_bytes - 1}")
            with urllib.request.urlopen(req, timeout=120) as resp:  # nosec B310
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    buf.write(chunk)
                    if buf.tell() >= self._max_download_bytes:
                        break

            raw_bytes = buf.getvalue()
            _logger.info(
                "azure_disk_connector: downloaded %d bytes from snapshot %s",
                len(raw_bytes),
                snapshot_id,
            )
            return SnapshotBlob(
                snapshot_id=snapshot_id,
                files={"__raw_disk__": raw_bytes},
                os_family="linux",
            )

        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "azure_disk_connector: fetch_snapshot failed for %s: %s",
                snapshot_id,
                exc,
            )
            return SnapshotBlob(snapshot_id=snapshot_id, files={}, os_family="unknown")

    def release(self, snapshot_id: str) -> None:
        """Revoke the SAS access grant for the snapshot."""
        resource_group = self._resource_group or ""
        if not resource_group:
            return
        try:
            client = self._client()
            client.snapshots.begin_revoke_access(
                resource_group_name=resource_group,
                snapshot_name=snapshot_id,
            )
            _logger.debug(
                "azure_disk_connector: revoked access for snapshot %s", snapshot_id
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "azure_disk_connector: revoke_access failed for %s: %s",
                snapshot_id,
                exc,
            )


__all__ = [
    "AzureDiskSnapshotConnector",
    "_azure_credentials_available",
]
