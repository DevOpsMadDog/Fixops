#!/usr/bin/env python3
"""Comprehensive UI test script for FixOps frontend."""

import json
from typing import Dict, List

import requests

# Test configuration
FRONTEND_URL = "http://localhost:3000"
BACKEND_URL = "http://localhost:8000"


def test_frontend_routes() -> Dict[str, bool]:
    """Test that key frontend routes are accessible."""
    print("\n=== TESTING FRONTEND ROUTES ===")

    routes = [
        "/",
        "/dashboard",
        "/ingest",
        "/intelligence",
        "/decisions",
        "/remediation",
        "/code/code-scanning",
        "/cloud/cloud-posture",
        "/attack/attack-simulation",
        "/protect/remediation",
        "/ai-engine/multi-llm",
        "/evidence/bundles",
        "/settings",
    ]

    results = {}
    for route in routes:
        try:
            response = requests.get(f"{FRONTEND_URL}{route}", timeout=5)
            status = response.status_code == 200
            results[route] = status
            emoji = "✅" if status else "❌"
            print(f"{emoji} {route}: {response.status_code}")
        except Exception as e:
            results[route] = False
            print(f"❌ {route}: Error - {e}")

    return results


def test_backend_health() -> bool:
    """Test backend health endpoint."""
    print("\n=== TESTING BACKEND HEALTH ===")

    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        if response.status_code == 200:
            print(f"✅ Backend health check passed: {response.json()}")
            return True
        else:
            print(f"⚠️ Backend health check returned: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Backend health check failed: {e}")
        return False


def test_api_endpoints() -> Dict[str, bool]:
    """Test key API endpoints."""
    print("\n=== TESTING API ENDPOINTS ===")

    endpoints = [
        "/api/v1/enhanced/capabilities",
        "/api/v1/health",
        "/api/v1/evidence/health",
        "/api/v1/policy/health",
    ]

    results = {}
    for endpoint in endpoints:
        try:
            response = requests.get(f"{BACKEND_URL}{endpoint}", timeout=5)
            # 200 is ideal, but 401 means the endpoint exists and requires auth
            status = response.status_code in [200, 401]
            results[endpoint] = status
            emoji = (
                "✅"
                if response.status_code == 200
                else "🔒"
                if response.status_code == 401
                else "❌"
            )
            print(f"{emoji} {endpoint}: {response.status_code}")

            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"   Response: {json.dumps(data, indent=2)[:200]}...")
                except:
                    pass
        except Exception as e:
            results[endpoint] = False
            print(f"❌ {endpoint}: Error - {e}")

    return results


def test_frontend_assets() -> bool:
    """Test that frontend assets are being served."""
    print("\n=== TESTING FRONTEND ASSETS ===")

    try:
        # Check if main HTML contains expected elements
        response = requests.get(FRONTEND_URL, timeout=5)
        html = response.text

        checks = {
            "Root div present": 'id="root"' in html,
            "Has script tags": "<script" in html,
            "Has Vite references": "vite" in html.lower() or "/src/" in html,
        }

        all_passed = True
        for check, passed in checks.items():
            emoji = "✅" if passed else "❌"
            print(f"{emoji} {check}")
            if not passed:
                all_passed = False

        return all_passed
    except Exception as e:
        print(f"❌ Asset check failed: {e}")
        return False


def main():
    """Run all tests and print summary."""
    print("=" * 60)
    print("FixOps UI Comprehensive Test Suite")
    print("=" * 60)

    # Run all tests
    frontend_routes = test_frontend_routes()
    backend_health = test_backend_health()
    api_endpoints = test_api_endpoints()
    frontend_assets = test_frontend_assets()

    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    total_route_tests = len(frontend_routes)
    passed_route_tests = sum(1 for v in frontend_routes.values() if v)
    print(f"Frontend Routes: {passed_route_tests}/{total_route_tests} passed")

    print(f"Backend Health: {'✅ PASSED' if backend_health else '❌ FAILED'}")

    total_api_tests = len(api_endpoints)
    passed_api_tests = sum(1 for v in api_endpoints.values() if v)
    print(f"API Endpoints: {passed_api_tests}/{total_api_tests} accessible")

    print(f"Frontend Assets: {'✅ PASSED' if frontend_assets else '❌ FAILED'}")

    # Overall status
    overall_passed = (
        passed_route_tests == total_route_tests
        and backend_health
        and passed_api_tests == total_api_tests
        and frontend_assets
    )

    print("\n" + "=" * 60)
    if overall_passed:
        print("🎉 ALL TESTS PASSED!")
    else:
        print("⚠️ SOME TESTS FAILED - See details above")
    print("=" * 60)

    print("\n📝 Next Steps for Manual Testing:")
    print("   1. Open http://localhost:3000 in your browser")
    print("   2. Navigate through different pages")
    print("   3. Test file upload functionality in /ingest")
    print("   4. Check decision engine in /decisions")
    print("   5. Verify AI engine features in /ai-engine/multi-llm")
    print("   6. Test remediation workflows in /remediation")


if __name__ == "__main__":
    main()
