#!/usr/bin/env python3.11
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    reports_dir = repo_root / "data" / "autonomous-reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_json = reports_dir / f"env-example-targeted-validation-{ts}.json"
    out_log = reports_dir / f"env-example-targeted-validation-{ts}.log"

    content = (repo_root / ".env.example").read_text()
    token = os.environ.get(
        "FIXOPS_API_TOKEN",
        "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
    )
    url = "http://127.0.0.1:8000/api/v1/secrets/scan/content"

    summary: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": ".env.example",
        "url": url,
    }

    try:
        resp = requests.post(
            url,
            headers={"X-API-Key": token, "Content-Type": "application/json"},
            json={"content": content, "filename": ".env.example"},
            timeout=60,
        )
        try:
            body = resp.json()
        except Exception:
            body = {"raw_text": resp.text}
        summary.update(
            {
                "http_status": resp.status_code,
                "secrets_found": body.get(
                    "total_findings",
                    body.get("secrets_found", len(body.get("findings", []))),
                )
                if isinstance(body, dict)
                else None,
                "findings": body.get("findings", []) if isinstance(body, dict) else [],
                "raw_body": body,
            }
        )
    except Exception as exc:
        summary.update(
            {
                "http_status": 0,
                "secrets_found": None,
                "findings": [],
                "error": f"{type(exc).__name__}: {exc}",
            }
        )

    out_json.write_text(json.dumps(summary, indent=2) + "\n")
    out_log.write_text(json.dumps(summary, indent=2) + "\n")
    print(out_json)
    print(out_log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
