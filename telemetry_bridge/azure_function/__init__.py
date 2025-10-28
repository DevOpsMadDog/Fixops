"""Azure Function for Event Hub telemetry ingestion."""

import json
import logging
import os
from typing import Any, Dict, List, Optional

import azure.functions as func
import requests

logger = logging.getLogger(__name__)


def load_overlay_config() -> Dict[str, Any]:
    """
    Load telemetry_bridge configuration from the overlay system.

    Reads from FIXOPS_OVERLAY_PATH env var or default config/fixops.overlay.yml.
    This ensures all configuration comes from the same source as the FixOps CLI/API.
    """
    overlay_path = os.environ.get(
        "FIXOPS_OVERLAY_PATH", "/home/site/wwwroot/config/fixops.overlay.yml"
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


def parse_event_hub_message(event: func.EventHubEvent) -> List[Dict[str, Any]]:
    """
    Parse Event Hub message from Azure Diagnostic Settings.

    Args:
        event: Event Hub event

    Returns:
        List of parsed log records
    """
    try:
        body = event.get_body().decode("utf-8")
        data = json.loads(body)

        if isinstance(data, dict) and "records" in data:
            return data["records"]
        elif isinstance(data, list):
            return data
        else:
            return [data]
    except Exception as e:
        logger.error(f"Failed to parse Event Hub message: {e}")
        return []


def aggregate_telemetry(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate log records into standardized telemetry format.

    Counts BLOCK/Blocked actions and extracts latency_ms_p95 if present.

    Args:
        records: List of Azure diagnostic log records

    Returns:
        Standardized telemetry dict matching ops-telemetry.schema.json
    """
    block_count = 0
    latencies: List[int] = []

    for record in records:
        try:
            properties = record.get("properties", {})

            action = properties.get("action", "").lower()
            if action in ["blocked", "block"]:
                block_count += 1

            latency = properties.get("latency_ms")
            if latency is not None and isinstance(latency, (int, float)):
                latencies.append(int(latency))

        except (KeyError, ValueError) as e:
            logger.warning(f"Failed to parse log record: {e}")
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

        logger.info(f"Sent telemetry to {fixops_url}: {response.status_code}")
        return {"ok": True, "status_code": response.status_code}

    elif mode == "file":
        output_path = os.environ.get("TELEMETRY_OUTPUT_PATH", "/tmp/ops-telemetry.json")
        with open(output_path, "w") as f:
            json.dump(telemetry, f, indent=2)

        logger.info(f"Wrote telemetry to {output_path}")
        return {"ok": True, "file": output_path}

    else:
        raise ValueError(f"Unknown telemetry mode: {mode}")


def main(event: func.EventHubEvent) -> None:
    """
    Azure Function entry point for Event Hub trigger.

    Args:
        event: Event Hub event from Azure Diagnostic Settings
    """
    try:
        config = load_overlay_config()

        records = parse_event_hub_message(event)
        logger.info(f"Parsed {len(records)} log records")

        telemetry = aggregate_telemetry(records)
        logger.info(f"Aggregated telemetry: {telemetry}")

        result = send_to_fixops(telemetry, config)
        logger.info(f"Result: {result}")

    except Exception as e:
        logger.error(f"Error processing telemetry: {e}", exc_info=True)
        raise
