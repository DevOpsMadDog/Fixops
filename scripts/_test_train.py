"""Test vuln discovery training endpoint end-to-end."""
import json
import os
import time
import urllib.error
import urllib.request

BASE = "http://localhost:8000"
TOKEN = os.environ.get("FIXOPS_API_TOKEN", "")
RESULTS = []


def call(method, path, body=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-API-Key", TOKEN)
    req.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()[:500]
        return e.code, body_text
    except Exception as e:
        return 0, str(e)


def test(name, method, path, body=None, expect_status=200, check_fn=None):
    code, data = call(method, path, body)
    ok = code == expect_status
    if ok and check_fn:
        ok = check_fn(data)
    status = "PASS" if ok else "FAIL"
    RESULTS.append(f"{status} | {name} | {code} | {json.dumps(data)[:200]}")
    return code, data


# Step 1: Health check
test("health", "GET", "/health")

# Step 2: Create test vulnerabilities for training data
for i in range(6):
    sevs = ["critical", "high", "medium", "low", "high", "critical"]
    impacts = [
        "remote_code_execution",
        "sql_injection",
        "cross_site_scripting",
        "authentication_bypass",
        "privilege_escalation",
        "denial_of_service",
    ]
    vectors = ["network", "adjacent", "local", "network", "network", "local"]
    diffs = ["trivial", "low", "medium", "high", "low", "trivial"]
    test(
        f"create_vuln_{i}",
        "POST",
        "/api/v1/vulns/discovered",
        {
            "title": f"Test Vuln {i} for ML Training",
            "description": f"Training sample {i} - {impacts[i]}",
            "severity": sevs[i],
            "impact_type": impacts[i],
            "attack_vector": vectors[i],
            "exploitation_difficulty": diffs[i],
            "cvss_score": [9.8, 7.5, 5.3, 3.1, 8.2, 9.1][i],
            "proof_of_concept": "PoC available" if i % 2 == 0 else None,
            "affected_components": [
                {"vendor": "test", "product": f"app{i}", "version": "1.0"}
            ],
        },
    )

# Step 3: Train with all 3 model types
code, data = test(
    "train_all_models",
    "POST",
    "/api/v1/vulns/train",
    {
        "model_types": [
            "severity_predictor",
            "exploitability_predictor",
            "zero_day_detector",
        ],
        "include_external": True,
        "force_retrain": True,
    },
)
job_id = data.get("job_id", "") if isinstance(data, dict) else ""

# Step 4: Wait for training to complete
if job_id:
    for attempt in range(10):
        time.sleep(2)
        code2, status_data = call("GET", f"/api/v1/vulns/train/{job_id}")
        if isinstance(status_data, dict):
            st = status_data.get("status", "")
            if st in ("completed", "partial", "failed"):
                RESULTS.append(
                    f"{'PASS' if st in ('completed', 'partial') else 'FAIL'} | training_status | {code2} | status={st}"
                )
                # Check each model result
                results = status_data.get("results", {})
                for model_name, model_result in results.items():
                    ms = model_result.get("status", "unknown")
                    algo = model_result.get("algorithm", "n/a")
                    RESULTS.append(
                        f"{'PASS' if ms == 'trained' else 'FAIL'} | model_{model_name} | {ms} | algo={algo} detail={json.dumps(model_result)[:150]}"
                    )
                break
    else:
        RESULTS.append(
            f"FAIL | training_timeout | 0 | Job {job_id} did not complete in 20s"
        )

# Step 5: Train with just severity_predictor (no external)
test(
    "train_severity_only",
    "POST",
    "/api/v1/vulns/train",
    {
        "model_types": ["severity_predictor"],
        "include_external": False,
    },
)

# Step 6: Train with unknown model type
test(
    "train_unknown_model",
    "POST",
    "/api/v1/vulns/train",
    {
        "model_types": ["unknown_model"],
        "include_external": True,
    },
)

# Step 7: Get stats
test("stats", "GET", "/api/v1/vulns/stats")

# Write results
out = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "_train_results.txt"
)
with open(out, "w") as f:
    passed = sum(1 for r in RESULTS if r.startswith("PASS"))
    failed = sum(1 for r in RESULTS if r.startswith("FAIL"))
    f.write(f"TRAIN TEST: {passed} PASS, {failed} FAIL, {len(RESULTS)} total\n")
    f.write("=" * 70 + "\n")
    for r in RESULTS:
        f.write(r + "\n")
print(f"DONE: {passed}/{len(RESULTS)} passed. Results in _train_results.txt")
