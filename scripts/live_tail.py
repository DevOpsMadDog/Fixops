#!/usr/bin/env python3
"""Live tail of API logs - watches for new requests and inspects responses."""
import json
import re
import sqlite3
import time

DB = ".fixops_data/api_detailed_logs.db"
SKIP = {"/api/v1/health", "/api/v1/logs/stats", "/api/v1/logs/recent", "/api/v1/logs"}

# Patterns that indicate fake/mocked data
FAKE_PATTERNS = [
    (r'"demo[_-]', "SUSPECT: contains 'demo' prefix"),
    (r'"test[-_]token', "SUSPECT: test token in response"),
    (r'"lorem ipsum"', "SUSPECT: lorem ipsum placeholder"),
    (r'"TODO"', "SUSPECT: TODO in response"),
    (r'"placeholder"', "SUSPECT: placeholder value"),
    (r'"example\.com"', "SUSPECT: example.com domain"),
    (r'"hardcoded"', "SUSPECT: hardcoded marker"),
    (r'"mock"', "SUSPECT: mock marker"),
    (r'"fake"', "SUSPECT: fake marker"),
]

# Patterns that indicate empty/useless 200 responses
EMPTY_PATTERNS = [
    (r"^\s*\{\s*\}\s*$", "EMPTY: empty object {}"),
    (r"^\s*\[\s*\]\s*$", "EMPTY: empty array []"),
    (r'"total":\s*0.*"items":\s*\[\]', "EMPTY: zero items"),
    (r'"count":\s*0.*"results":\s*\[\]', "EMPTY: zero results"),
]


def analyze_response(method, path, status, body, duration):
    """Analyze a response for suspicious content."""
    issues = []
    if not body or body == "null":
        if method == "GET" and status == 200:
            issues.append("WARN: GET 200 but null body")
        return issues

    # Check for fake patterns
    for pat, msg in FAKE_PATTERNS:
        if re.search(pat, body, re.IGNORECASE):
            issues.append(msg)

    # Check for empty responses on GET
    if method == "GET" and status == 200:
        for pat, msg in EMPTY_PATTERNS:
            if re.search(pat, body):
                issues.append(msg)

    # Check for suspiciously fast complex operations
    if duration is not None and duration < 1.0 and method == "POST":
        if any(k in path for k in ["/pipeline/run", "/scan", "/pentest", "/attack"]):
            issues.append(f"SUSPECT: complex operation completed in {duration:.1f}ms")

    # Try to parse JSON and check for hardcoded values
    try:
        d = json.loads(body)
        if isinstance(d, dict):
            # Check for static timestamps that never change
            for k in ("timestamp", "created_at", "updated_at"):
                v = d.get(k, "")
                if isinstance(v, str) and "2024-01-01" in v:
                    issues.append(f"SUSPECT: static date 2024-01-01 in {k}")
            # Check for suspiciously round numbers
            for k in ("score", "risk_score", "confidence"):
                v = d.get(k)
                if isinstance(v, (int, float)) and v in (0, 42, 42.5, 50, 100, 99.9):
                    issues.append(f"SUSPECT: round/magic number {k}={v}")
    except (json.JSONDecodeError, TypeError):
        pass

    return issues


def main():
    print("LIVE API LOG TAIL - watching for new requests...")
    print("=" * 70)
    db = sqlite3.connect(DB)
    # Get current max rowid
    last_rowid = db.execute("SELECT MAX(rowid) FROM api_logs").fetchone()[0] or 0
    print(f"Starting from rowid > {last_rowid}")
    print()

    try:
        while True:
            rows = list(
                db.execute(
                    "SELECT rowid, ts, method, path, status_code, duration_ms, "
                    "req_body, resp_body, query_params "
                    "FROM api_logs WHERE rowid > ? ORDER BY rowid ASC",
                    (last_rowid,),
                )
            )
            for r in rows:
                rowid, ts, method, path, status, dur, req_body, resp_body, qparams = r
                last_rowid = rowid
                if any(path.startswith(s) for s in SKIP):
                    continue

                # Format timestamp
                t = ts.split("T")[1][:8] if "T" in (ts or "") else "?"
                dur_s = f"{dur:.0f}ms" if dur else "?ms"

                # Status emoji
                if status >= 500:
                    emoji = "🔴"
                elif status >= 400:
                    emoji = "🟡"
                elif status >= 200 and status < 300:
                    emoji = "🟢"
                else:
                    emoji = "⚪"

                print(f"{emoji} {t} {method:4s} {path:<55s} {status} ({dur_s})")

                # Show request body for POST/PUT/PATCH
                if (
                    method in ("POST", "PUT", "PATCH")
                    and req_body
                    and req_body != "null"
                ):
                    body_preview = req_body[:200]
                    print(f"   REQ: {body_preview}")

                # Show response body preview
                if resp_body and resp_body != "null":
                    body_preview = resp_body[:250]
                    print(f"   RSP: {body_preview}")

                # Analyze for issues
                issues = analyze_response(method, path, status, resp_body, dur)
                for issue in issues:
                    print(f"   ⚠️  {issue}")

                if issues:
                    print()

            time.sleep(1.5)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
