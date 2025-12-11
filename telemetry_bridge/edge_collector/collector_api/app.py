"""FastAPI Edge Collector for telemetry aggregation and evidence generation."""

import gzip
import hashlib
import json
import logging
import os
import re
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class TelemetryPayload(BaseModel):
    """Standardized telemetry payload matching ops-telemetry.schema.json."""

    alerts: List[Dict[str, Any]]
    latency_ms_p95: Optional[int]


class RingBuffer:
    """Thread-safe ring buffer for raw log retention."""

    def __init__(self, max_lines: int, max_seconds: int):
        self.max_lines = max_lines
        self.max_seconds = max_seconds
        self.buffer: deque = deque(maxlen=max_lines)
        self.lock = Lock()

    def append(self, line: str) -> None:
        """Add a line to the buffer with timestamp."""
        with self.lock:
            entry = {"timestamp": time.time(), "line": line}
            self.buffer.append(entry)

    def get_lines(
        self, since_seconds: Optional[int] = None, asset: Optional[str] = None
    ) -> List[str]:
        """
        Retrieve lines from buffer.

        Args:
            since_seconds: Only return lines from last N seconds
            asset: Filter by asset ID (if present in line)

        Returns:
            List of raw log lines
        """
        with self.lock:
            now = time.time()
            lines = []

            for entry in self.buffer:
                if since_seconds and (now - entry["timestamp"]) > since_seconds:
                    continue

                if asset and asset not in entry["line"]:
                    continue

                lines.append(entry["line"])

            return lines


def load_overlay_config() -> Dict[str, Any]:
    """
    Load telemetry_bridge configuration from the overlay system.

    Reads from FIXOPS_OVERLAY_PATH env var or default config/fixops.overlay.yml.
    This ensures all configuration comes from the same source as the FixOps CLI/API.
    """
    overlay_path = os.environ.get(
        "FIXOPS_OVERLAY_PATH", "/app/config/fixops.overlay.yml"
    )

    try:
        import yaml

        with open(overlay_path, "r") as f:
            overlay = yaml.safe_load(f)
        return overlay.get("telemetry_bridge", {})
    except Exception as e:
        logger.warning(f"Failed to load overlay from {overlay_path}: {e}")
        return {
            "mode": os.environ.get("TELEMETRY_MODE", "http"),
            "fixops_url": os.environ.get("FIXOPS_URL", ""),
            "api_key_secret_ref": os.environ.get("API_KEY_SECRET_REF", ""),
            "ring_buffer": {
                "max_lines": int(os.environ.get("RING_BUFFER_MAX_LINES", "200000")),
                "max_seconds": int(os.environ.get("RING_BUFFER_MAX_SECONDS", "21600")),
            },
        }


config = load_overlay_config()
ring_buffer_config = config.get("ring_buffer", {})
ring_buffer = RingBuffer(
    max_lines=ring_buffer_config.get("max_lines", 200000),
    max_seconds=ring_buffer_config.get("max_seconds", 21600),
)

app = FastAPI(
    title="FixOps Edge Collector",
    description="Telemetry aggregation and evidence generation",
    version="1.0.0",
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/telemetry")
async def ingest_telemetry(payload: TelemetryPayload):
    """
    Ingest aggregated telemetry summaries.

    Forwards to FixOps (http mode) or writes to file (file mode).
    Also stores raw representation in ring buffer.
    """
    try:
        raw_line = json.dumps(payload.dict())
        ring_buffer.append(raw_line)

        mode = config.get("mode", "http")

        if mode == "http":
            fixops_url = config.get("fixops_url", "")
            if not fixops_url:
                raise HTTPException(
                    status_code=500,
                    detail="fixops_url not configured in telemetry_bridge overlay",
                )

            api_key_ref = config.get("api_key_secret_ref", "FIXOPS_API_KEY")
            api_key = os.environ.get(api_key_ref, "")

            headers = {"Content-Type": "application/json", "X-API-Key": api_key}

            response = requests.post(
                fixops_url, json=payload.dict(), headers=headers, timeout=10
            )
            response.raise_for_status()

            logger.info(f"Successfully forwarded telemetry: {response.status_code}")
            return {"ok": True, "status_code": response.status_code}

        elif mode == "file":
            output_path = os.environ.get(
                "TELEMETRY_OUTPUT_PATH", "/app/demo_decision_inputs/ops-telemetry.json"
            )

            Path(output_path).parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w") as f:
                json.dump(payload.dict(), f, indent=2)

            logger.info("Successfully wrote telemetry to file")
            return {"ok": True, "file": output_path}

        else:
            raise HTTPException(
                status_code=500, detail=f"Unknown telemetry mode: {mode}"
            )

    except requests.RequestException as e:
        logger.error(f"Failed to forward telemetry: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to forward telemetry: {e}")
    except Exception as e:
        logger.error(f"Error processing telemetry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/evidence")
async def generate_evidence(
    since: int = Query(default=3600, description="Retrieve logs from last N seconds"),
    asset: Optional[str] = Query(default=None, description="Filter by asset ID"),
):
    """
    Generate evidence bundle from ring buffer.

    Returns compressed JSONL bundle with SHA256 hash and uploads to cloud storage.
    """
    try:
        lines = ring_buffer.get_lines(since_seconds=since, asset=asset)

        if not lines:
            return {
                "ok": True,
                "line_count": 0,
                "message": "No logs found matching criteria",
            }

        jsonl_content = "\n".join(lines)

        compressed = gzip.compress(jsonl_content.encode("utf-8"))

        sha256_hash = hashlib.sha256(compressed).hexdigest()

        metadata = {
            "timestamp": datetime.utcnow().isoformat(),
            "line_count": len(lines),
            "since_seconds": since,
            "asset": asset,
            "sha256": sha256_hash,
            "compressed_size_bytes": len(compressed),
        }

        upload_result = upload_evidence_bundle(
            compressed_data=compressed, metadata=metadata
        )

        return {"ok": True, "metadata": metadata, "upload": upload_result}

    except Exception as e:
        logger.error(f"Error generating evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal attacks.

    Removes any path separators and keeps only alphanumeric, dash, dot, and underscore.
    """
    # First strip any directory components
    safe_filename = Path(filename).name
    # Then remove any remaining unsafe characters
    safe_filename = re.sub(r"[^a-zA-Z0-9._-]", "_", safe_filename)
    safe_filename = safe_filename.replace("..", "_")
    return safe_filename


def _validate_path_within_base(path: Path, base: Path) -> Path:
    """Validate that a path is within the expected base directory."""
    resolved_path = path.resolve()
    resolved_base = base.resolve()
    if not resolved_path.is_relative_to(resolved_base):
        raise ValueError(f"Path {path} is outside base directory {base}")
    return resolved_path


def upload_evidence_bundle(
    compressed_data: bytes, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Upload evidence bundle to cloud object store (S3/Blob/GCS).

    Uses cloud-specific SDK based on environment.
    """
    cloud_provider = os.environ.get("CLOUD_PROVIDER", "").lower()

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    sha256_prefix = sanitize_filename(metadata["sha256"][:8])
    filename = f"evidence-{timestamp}-{sha256_prefix}.jsonl.gz"

    if cloud_provider == "aws":
        return upload_to_s3(compressed_data, filename, metadata)
    elif cloud_provider == "azure":
        return upload_to_azure_blob(compressed_data, filename, metadata)
    elif cloud_provider == "gcp":
        return upload_to_gcs(compressed_data, filename, metadata)
    else:
        evidence_base = Path("/app/evidence").resolve()
        evidence_base.mkdir(parents=True, exist_ok=True)
        # Sanitize filename and validate path is within evidence directory
        safe_filename = sanitize_filename(filename)
        local_path = evidence_base / safe_filename
        _validate_path_within_base(local_path, evidence_base)
        local_path.write_bytes(compressed_data)

        metadata_path = local_path.with_suffix(".json")
        _validate_path_within_base(metadata_path, evidence_base)
        metadata_path.write_text(json.dumps(metadata, indent=2))

        logger.info("Successfully saved evidence bundle locally")
        return {
            "provider": "local",
            "path": str(local_path),
            "metadata_path": str(metadata_path),
        }


def upload_to_s3(
    data: bytes, filename: str, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Upload to AWS S3."""
    try:
        import boto3

        s3_bucket = config.get("aws", {}).get("s3_bucket", "")
        if not s3_bucket:
            raise ValueError("S3 bucket not configured")

        s3_client = boto3.client("s3")

        s3_client.put_object(
            Bucket=s3_bucket,
            Key=f"evidence/{filename}",
            Body=data,
            Metadata={
                "sha256": metadata["sha256"],
                "line_count": str(metadata["line_count"]),
                "timestamp": metadata["timestamp"],
            },
            ContentType="application/gzip",
        )

        logger.info("Successfully uploaded evidence to S3")
        return {
            "provider": "aws",
            "bucket": s3_bucket,
            "key": f"evidence/{filename}",
            "url": f"s3://{s3_bucket}/evidence/{filename}",
        }
    except Exception as e:
        logger.error(f"Failed to upload to S3: {e}")
        raise


def upload_to_azure_blob(
    data: bytes, filename: str, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Upload to Azure Blob Storage."""
    try:
        from azure.storage.blob import BlobServiceClient

        storage_account = config.get("azure", {}).get("storage_account", "")
        if not storage_account:
            raise ValueError("Azure storage account not configured")

        connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "")

        blob_service_client = BlobServiceClient.from_connection_string(
            connection_string
        )
        container_client = blob_service_client.get_container_client("evidence")

        try:
            container_client.create_container()
        except Exception:
            pass  # Container already exists

        blob_client = container_client.get_blob_client(filename)
        blob_client.upload_blob(
            data,
            metadata={
                "sha256": metadata["sha256"],
                "line_count": str(metadata["line_count"]),
                "timestamp": metadata["timestamp"],
            },
            overwrite=True,
        )

        logger.info("Successfully uploaded evidence to Azure Blob")
        return {
            "provider": "azure",
            "storage_account": storage_account,
            "container": "evidence",
            "blob": filename,
            "url": f"https://{storage_account}.blob.core.windows.net/evidence/{filename}",
        }
    except Exception as e:
        logger.error(f"Failed to upload to Azure Blob: {e}")
        raise


def upload_to_gcs(
    data: bytes, filename: str, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Upload to Google Cloud Storage."""
    try:
        from google.cloud import storage

        gcs_bucket = config.get("gcp", {}).get("gcs_bucket", "")
        if not gcs_bucket:
            raise ValueError("GCS bucket not configured")

        storage_client = storage.Client()
        bucket = storage_client.bucket(gcs_bucket)
        blob = bucket.blob(f"evidence/{filename}")

        blob.metadata = {
            "sha256": metadata["sha256"],
            "line_count": str(metadata["line_count"]),
            "timestamp": metadata["timestamp"],
        }

        blob.upload_from_string(data, content_type="application/gzip")

        logger.info("Successfully uploaded evidence to GCS")
        return {
            "provider": "gcp",
            "bucket": gcs_bucket,
            "blob": f"evidence/{filename}",
            "url": f"gs://{gcs_bucket}/evidence/{filename}",
        }
    except Exception as e:
        logger.error(f"Failed to upload to GCS: {e}")
        raise


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
