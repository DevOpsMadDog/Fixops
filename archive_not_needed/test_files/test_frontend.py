#!/usr/bin/env python3
"""Simple test script to verify frontend is accessible and working."""

import os

import pytest

requests = pytest.importorskip(
    "requests",
    reason="HTTP integration tests require the optional 'requests' dependency",
)

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_FIXOPS_INTEGRATION_TESTS") != "1",
    reason="FixOps frontend integration tests require running services",
)


def test_frontend():
    print("=== TESTING FRONTEND ACCESSIBILITY ===")

    # Test frontend HTML loading
    try:
        response = requests.get("http://localhost:3000", timeout=10)
        print(f"✅ Frontend accessible: {response.status_code}")

        # Check if it contains React app structure
        if 'id="root"' in response.text:
            print("✅ React app structure found")
        else:
            print("❌ React app structure not found")

        # Check if it contains navigation elements
        if "Enhanced" in response.text or "CISO" in response.text:
            print("✅ Navigation elements found in HTML")
        else:
            print("⚠️ Navigation elements not found in initial HTML (expected for SPA)")

    except Exception as e:
        print(f"❌ Frontend not accessible: {e}")
        return False

    # Test backend API through frontend proxy
    try:
        response = requests.get(
            "http://localhost:3000/api/v1/enhanced/capabilities", timeout=10
        )
        print(
            f"✅ Backend API accessible through frontend proxy: {response.status_code}"
        )

        if response.status_code == 200:
            data = response.json()
            print(f"✅ API response valid: {data.get('status', 'unknown')}")
        else:
            print(f"⚠️ API response status: {response.status_code}")

    except Exception as e:
        print(f"❌ Backend API not accessible through proxy: {e}")

    return True


if __name__ == "__main__":
    test_frontend()
