import json
import subprocess

r1 = subprocess.run(
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
)
print(f"Health: HTTP {r1.stdout}")
r2 = subprocess.run(
    [
        "curl",
        "-s",
        "-H",
        "X-API-Key: test-token-123",
        "http://localhost:8000/api/v1/cases",
    ],
    capture_output=True,
    text=True,
)
try:
    d2 = json.loads(r2.stdout)
    print(f"Cases: total={d2.get('total','?')} count={len(d2.get('cases',[]))}")
    if d2.get("cases"):
        c0 = d2["cases"][0]
        print(f"  First case fields: {list(c0.keys())[:15]}")
        print(
            f"  finding_count={c0.get('finding_count','MISSING')} cluster_ids={c0.get('cluster_ids','MISSING')}"
        )
except Exception as e:
    print(f"Cases ERROR: {e} | {r2.stdout[:200]}")
r3 = subprocess.run(
    [
        "curl",
        "-s",
        "-H",
        "X-API-Key: test-token-123",
        "http://localhost:8000/api/v1/cases/stats/summary",
    ],
    capture_output=True,
    text=True,
)
try:
    d3 = json.loads(r3.stdout)
    print(
        f"Stats: total_cases={d3.get('total_cases','?')} avg_risk={d3.get('avg_risk_score','?')} kev={d3.get('kev_cases','?')}"
    )
except Exception as e:
    print(f"Stats ERROR: {e} | {r3.stdout[:200]}")
