#!/usr/bin/env python3
"""Quick report test - starts server, runs tests, writes results to _rtest3.txt.

Run from project root:
  PYTHONPATH=suite-core:suite-api:suite-attack:suite-feeds:. .venv/bin/python3 scripts/_quick_report_test.py
"""
import json
import os
import signal
import subprocess
import sys
import time
import traceback
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = open("/tmp/fixops_enterprise_token.txt").read().strip()
BASE = "http://127.0.0.1:8000/api/v1/reports"
OUT = os.path.join(ROOT, "_rtest3.txt")


def _write(lines):
    with open(OUT, "w") as f:
        f.write("\n".join(lines) + "\n")


def kill_port(port=8000):
    try:
        pids = subprocess.check_output(
            ["lsof", "-ti", f":{port}"], text=True, timeout=5
        ).strip()
        for pid in pids.split("\n"):
            if pid.strip():
                os.kill(int(pid.strip()), signal.SIGKILL)
        time.sleep(2)
    except Exception:
        pass


def start_server():
    env = os.environ.copy()
    env["FIXOPS_DEMO_MODE"] = "false"
    env["FIXOPS_JWT_SECRET_KEY"] = "test-secret-key-for-reports-testing-1234"
    env["FIXOPS_API_TOKEN"] = TOKEN
    env["PYTHONPATH"] = "suite-core:suite-api:suite-attack:suite-feeds:."
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "suite-api.apps.api.app:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--workers",
            "1",
        ],
        cwd=ROOT,
        env=env,
        stdout=open("/tmp/server_start.log", "w"),
        stderr=subprocess.STDOUT,
    )
    return proc


def wait_for_server(timeout=45):
    for i in range(timeout):
        try:
            r = urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=2)
            if r.status == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def post_report(body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        BASE,
        data=data,
        headers={"X-API-Key": TOKEN, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


try:
    lines = ["=== Starting server ==="]
    kill_port(8000)
    proc = start_server()
    lines.append("=== Waiting for server (up to 45s) ===")
    _write(lines)  # Write early so we can see progress

    if not wait_for_server():
        lines.append("SERVER FAILED TO START")
        _write(lines)
        proc.kill()
        sys.exit(1)
    lines.append("Server UP")
    _write(lines)

    tests = [
        (
            "JSON",
            {
                "name": "JSON Test",
                "report_type": "security_summary",
                "format": "json",
                "parameters": {"limit": 50},
            },
        ),
        (
            "CSV",
            {
                "name": "CSV Test",
                "report_type": "vulnerability",
                "format": "csv",
                "parameters": {},
            },
        ),
        (
            "HTML",
            {
                "name": "HTML Test",
                "report_type": "risk_assessment",
                "format": "html",
                "parameters": {},
            },
        ),
        (
            "SARIF",
            {
                "name": "SARIF Test",
                "report_type": "vulnerability",
                "format": "sarif",
                "parameters": {},
            },
        ),
        (
            "PDF",
            {
                "name": "PDF Test",
                "report_type": "compliance",
                "format": "pdf",
                "parameters": {},
            },
        ),
    ]

    report_ids = []
    for label, body in tests:
        r = post_report(body)
        status = r.get("status", "?")
        fsize = r.get("file_size") or 0
        fpath = r.get("file_path") or ""
        err = r.get("error_message") or r.get("error") or ""
        rid = r.get("id", "")
        ok = "PASS" if status == "completed" and fsize > 0 else "FAIL"
        lines.append(
            f"{ok} | {label:6s} | status={status} size={fsize} path={fpath} err={err}"
        )
        if rid:
            report_ids.append(rid)
        _write(lines)

    # Test /generate alias
    rg = post_report(
        {
            "name": "Generate Alias",
            "report_type": "audit",
            "format": "json",
            "parameters": {},
        }
    )
    status = rg.get("status", "?")
    fsize = rg.get("file_size") or 0
    err = rg.get("error_message") or rg.get("error") or ""
    ok = "PASS" if status == "completed" and fsize > 0 else "FAIL"
    lines.append(f"{ok} | GENERATE | status={status} size={fsize} err={err}")
    _write(lines)

    # Test download
    if report_ids:
        rid = report_ids[0]
        try:
            req = urllib.request.Request(
                f"{BASE}/{rid}/download", headers={"X-API-Key": TOKEN}
            )
            resp = urllib.request.urlopen(req, timeout=10)
            dl = json.loads(resp.read())
            ok = "PASS" if "download_url" in dl else "FAIL"
            lines.append(f"{ok} | DOWNLOAD | url={dl.get('download_url', '')}")
        except Exception as e:
            lines.append(f"FAIL | DOWNLOAD | {e}")

        try:
            req = urllib.request.Request(
                f"{BASE}/{rid}/file", headers={"X-API-Key": TOKEN}
            )
            resp = urllib.request.urlopen(req, timeout=10)
            content = resp.read()
            ok = "PASS" if len(content) > 0 else "FAIL"
            lines.append(f"{ok} | FILE_DL  | bytes={len(content)}")
        except Exception as e:
            lines.append(f"FAIL | FILE_DL  | {e}")

    # Summary
    passed = sum(1 for ln in lines if ln.startswith("PASS"))
    total = sum(1 for ln in lines if ln.startswith("PASS") or ln.startswith("FAIL"))
    lines.append(f"\n{passed}/{total} PASSED")
    _write(lines)

except Exception:
    lines.append(f"\nERROR: {traceback.format_exc()}")
    _write(lines)
