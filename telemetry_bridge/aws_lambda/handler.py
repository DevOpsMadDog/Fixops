"""AWS Lambda handler for CloudWatch Logs telemetry ingestion."""

import base64
import gzip
import json
import logging
import os
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def load_overlay_config() -> Dict[str, Any]:
    """
    Load telemetry_bridge configuration from the overlay system.

    Reads from FIXOPS_OVERLAY_PATH env var or default config/fixops.overlay.yml.
    This ensures all configuration comes from the same source as the FixOps CLI/API.
    """
    overlay_path = os.environ.get(
        "FIXOPS_OVERLAY_PATH", "/opt/config/fixops.overlay.yml"
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
        }


def parse_cloudwatch_logs(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse CloudWatch Logs subscription event.

    Args:
        event: CloudWatch Logs event with base64-encoded gzipped data

    Returns:
        List of parsed log events
    """
    compressed_payload = base64.b64decode(event["awslogs"]["data"])
    uncompressed_payload = gzip.decompress(compressed_payload)
    log_data = json.loads(uncompressed_payload)

    return log_data.get("logEvents", [])


def aggregate_telemetry(log_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate log events into standardized telemetry format.

    Counts BLOCK actions and extracts latency_ms_p95 if present.

    Args:
        log_events: List of CloudWatch log events

    Returns:
        Standardized telemetry dict matching ops-telemetry.schema.json
    """
    block_count = 0
    latencies: List[int] = []

    for event in log_events:
        try:
            message = event.get("message", "")
            if isinstance(message, str):
                log_entry = json.loads(message)
            else:
                log_entry = message

            action = log_entry.get("action", "").upper()
            if action == "BLOCK":
                block_count += 1

            latency = log_entry.get("latency_ms")
            if latency is not None and isinstance(latency, (int, float)):
                latencies.append(int(latency))

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse log event: {e}")
            continue

    latency_p95: Optional[int] = None
    if latencies:
        latencies.sort()
        p95_index = int(len(latencies) * 0.95)
        latency_p95 = (
            latencies[p95_index] if p95_index < len(latencies) else latencies[-1]
        )

    return {
        "alerts": [{"rule": "waf-blocks", "count": block_count}],
        "latency_ms_p95": latency_p95,
    }


def send_to_fixops(telemetry: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send telemetry to FixOps via HTTP or write to file.

    Args:
        telemetry: Aggregated telemetry data
        config: Configuration from overlay

    Returns:
        Response dict with ok status
    """
    mode = config.get("mode", "http")

    if mode == "http":
        fixops_url = config.get("fixops_url", "")
        if not fixops_url:
            raise ValueError("fixops_url not configured in telemetry_bridge overlay")

        api_key_ref = config.get("api_key_secret_ref", "FIXOPS_API_KEY")
        api_key = os.environ.get(api_key_ref, "")

        headers = {"Content-Type": "application/json", "X-API-Key": api_key}

        response = requests.post(
            fixops_url, json=telemetry, headers=headers, timeout=10
        )
        response.raise_for_status()

        logger.info(f"Successfully sent telemetry: {response.status_code}")
        return {"ok": True, "status_code": response.status_code}

    elif mode == "file":
        output_path = os.environ.get("TELEMETRY_OUTPUT_PATH", "/tmp/ops-telemetry.json")
        with open(output_path, "w") as f:
            json.dump(telemetry, f, indent=2)

        logger.info("Successfully wrote telemetry to file")
        return {"ok": True, "file": output_path}

    else:
        raise ValueError(f"Unknown telemetry mode: {mode}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for CloudWatch Logs subscription.

    Args:
        event: CloudWatch Logs event
        context: Lambda context

    Returns:
        Response dict with ok status
    """
    try:
        config = load_overlay_config()

        log_events = parse_cloudwatch_logs(event)
        logger.info(f"Parsed {len(log_events)} log events")

        telemetry = aggregate_telemetry(log_events)
        logger.info(f"Aggregated telemetry: {telemetry}")

        result = send_to_fixops(telemetry, config)

        return result

    except Exception as e:
        logger.error(f"Error processing telemetry: {e}", exc_info=True)
        return {"ok": False, "error": str(e)}
