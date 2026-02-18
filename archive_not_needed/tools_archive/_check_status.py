#!/usr/bin/env python3
"""Check backend and frontend status, write results to tools/_status_result.txt"""
import json
import os
import subprocess

results = []

# Check port 8000 (backend)
p = subprocess.run(["lsof", "-ti:8000"], capture_output=True, text=True)
backend_up = bool(p.stdout.strip())
results.append(f"BACKEND: {'UP' if backend_up else 'DOWN'}")

# Check port 3001 (frontend)
p = subprocess.run(["lsof", "-ti:3001"], capture_output=True, text=True)
frontend_up = bool(p.stdout.strip())
results.append(f"FRONTEND: {'UP' if frontend_up else 'DOWN'}")

# Check health endpoint
if backend_up:
    h = subprocess.run(
        [
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "http://localhost:8000/api/v1/health",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    results.append(f"HEALTH_CODE: {h.stdout.strip()}")

    # Check micro-pentest status
    mp = subprocess.run(
        ["curl", "-s", "http://localhost:8000/api/v1/micro-pentest/status"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    results.append(f"MICROPENTEST_STATUS: {mp.stdout.strip()[:300]}")
else:
    results.append("HEALTH_CODE: N/A (backend down)")
    results.append("MICROPENTEST_STATUS: N/A (backend down)")

# Write to file
output_path = os.path.join(os.path.dirname(__file__), "_status_result.txt")
with open(output_path, "w") as f:
    f.write("\n".join(results) + "\n")

# Also print
for r in results:
    print(r)
