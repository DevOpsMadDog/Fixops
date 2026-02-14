#!/usr/bin/env python3
"""
Demo script for Golden Regression Sets feature.

This demonstrates how FixOps validates decisions against historical cases
to ensure consistency over time.
"""

import json
import sys
from pathlib import Path

ENTERPRISE_LEGACY_ROOT = (
    Path(__file__).resolve().parent / "WIP" / "code" / "enterprise_legacy"
)
if str(ENTERPRISE_LEGACY_ROOT) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_LEGACY_ROOT))

import types

if "structlog" not in sys.modules:
    structlog_stub = types.ModuleType("structlog")

    class _Logger:
        def __getattr__(self, _name):
            def _noop(*_args, **_kwargs):
                return None

            return _noop

    def get_logger(*_args, **_kwargs):
        return _Logger()

    structlog_stub.get_logger = get_logger
    sys.modules["structlog"] = structlog_stub

from src.services.golden_regression_store import GoldenRegressionStore


def print_section(title):
    """Print a section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def demo_load_dataset():
    """Demo: Load the golden regression dataset."""
    print_section("1. Loading Golden Regression Dataset")

    store = GoldenRegressionStore.get_instance()

    print(f"✅ Loaded {len(store._cases_by_id)} historical cases")
    print(f"   - Services tracked: {len(store._cases_by_service)}")
    print(f"   - CVEs tracked: {len(store._cases_by_cve)}")

    print("\n📋 Sample case IDs:")
    for case_id in list(store._cases_by_id.keys())[:5]:
        case = store._cases_by_id[case_id]
        print(
            f"   - {case_id}: {case.service_name} | {case.decision} | confidence={case.confidence}"
        )


def demo_lookup_by_service():
    """Demo: Lookup cases by service name."""
    print_section("2. Lookup by Service Name")

    store = GoldenRegressionStore.get_instance()

    service_name = "payment-service"
    print(f"🔍 Looking up cases for service: {service_name}")

    lookup = store.lookup_cases(service_name=service_name)

    print(f"\n✅ Found {lookup['service_matches']} cases for {service_name}")

    for case in lookup["cases"]:
        print(f"\n   Case: {case['case_id']}")
        print(f"   - Decision: {case['decision']}")
        print(f"   - Confidence: {case['confidence']}")
        print(f"   - CVE: {case.get('cve_id', 'N/A')}")
        print(f"   - Timestamp: {case.get('timestamp', 'N/A')}")


def demo_lookup_by_cve():
    """Demo: Lookup cases by CVE ID."""
    print_section("3. Lookup by CVE (Log4Shell)")

    store = GoldenRegressionStore.get_instance()

    cve_id = "CVE-2021-44228"  # Log4Shell
    print(f"🔍 Looking up cases for CVE: {cve_id} (Log4Shell)")

    lookup = store.lookup_cases(cve_ids=[cve_id])

    print(f"\n✅ Found {lookup['cve_matches'][cve_id]} case(s) for {cve_id}")

    for case in lookup["cases"]:
        print(f"\n   Case: {case['case_id']}")
        print(f"   - Service: {case['service_name']}")
        print(f"   - Decision: {case['decision']}")
        print(f"   - Confidence: {case['confidence']}")
        print(f"   - Rationale: {case.get('metadata', {}).get('rationale', 'N/A')}")


def demo_lookup_combined():
    """Demo: Lookup by both service and CVE."""
    print_section("4. Combined Lookup (Service + CVE)")

    store = GoldenRegressionStore.get_instance()

    service_name = "payment-service"
    cve_id = "CVE-2024-1111"

    print("🔍 Looking up cases for:")
    print(f"   - Service: {service_name}")
    print(f"   - CVE: {cve_id}")

    lookup = store.lookup_cases(service_name=service_name, cve_ids=[cve_id])

    print("\n✅ Results:")
    print(f"   - Service matches: {lookup['service_matches']}")
    print(f"   - CVE matches: {lookup['cve_matches'][cve_id]}")
    print(f"   - Total cases: {len(lookup['cases'])}")

    for case in lookup["cases"]:
        print(f"\n   Case: {case['case_id']}")
        print(f"   - Decision: {case['decision']}")
        print(f"   - Confidence: {case['confidence']}")
        print(f"   - Match context: {[m['type'] for m in case['match_context']]}")


def demo_validation_scenario():
    """Demo: Show how validation would work."""
    print_section("5. Decision Validation Scenario")

    store = GoldenRegressionStore.get_instance()

    print("📝 Scenario: New vulnerability detected in payment-service")
    print("   - Service: payment-service")
    print("   - CVE: CVE-2024-1111")
    print("   - Current decision: BLOCK")
    print("   - Confidence: 0.95")

    lookup = store.lookup_cases(
        service_name="payment-service", cve_ids=["CVE-2024-1111"]
    )

    print("\n🔍 Checking against historical cases...")
    print(f"   Found {len(lookup['cases'])} historical case(s)")

    for case in lookup["cases"]:
        historical_decision = case["decision"]
        current_decision = "fail"  # "BLOCK" normalized to "fail"

        if historical_decision == current_decision:
            print(f"\n   ✅ CONSISTENT with case {case['case_id']}")
            print(
                f"      Historical: {historical_decision} (confidence={case['confidence']})"
            )
            print(f"      Current: {current_decision} (confidence=0.95)")
        else:
            print(f"\n   ⚠️  REGRESSION DETECTED in case {case['case_id']}")
            print(
                f"      Historical: {historical_decision} (confidence={case['confidence']})"
            )
            print(f"      Current: {current_decision} (confidence=0.95)")
            print("      Action: Flag for review")


def demo_dataset_stats():
    """Demo: Show dataset statistics."""
    print_section("6. Dataset Statistics")

    dataset_path = (
        Path(__file__).resolve().parent / "data" / "golden_regression_cases.json"
    )

    with open(dataset_path) as f:
        data = json.load(f)

    cases = data["cases"]

    print("📊 Golden Regression Dataset Statistics:")
    print(f"   - Total cases: {len(cases)}")

    decisions = {}
    for case in cases:
        decision = case["decision"]
        decisions[decision] = decisions.get(decision, 0) + 1

    print("\n   Decisions:")
    for decision, count in decisions.items():
        print(f"   - {decision}: {count}")

    services = {}
    for case in cases:
        service = case["service_name"]
        services[service] = services.get(service, 0) + 1

    print("\n   Services:")
    for service, count in sorted(services.items()):
        print(f"   - {service}: {count}")

    cves = [case["cve_id"] for case in cases if case.get("cve_id")]
    print(f"\n   CVEs tracked: {len(cves)}")
    print("   Notable CVEs:")
    for cve in cves[:5]:
        print(f"   - {cve}")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  FixOps Golden Regression Sets - Feature Demo")
    print("  Ensuring Decision Consistency Over Time")
    print("=" * 80)

    try:
        demo_load_dataset()
        demo_lookup_by_service()
        demo_lookup_by_cve()
        demo_lookup_combined()
        demo_validation_scenario()
        demo_dataset_stats()

        print_section("Demo Complete!")
        print("✅ Golden Regression Sets feature is working correctly")
        print("\n💡 Key Takeaways:")
        print("   1. Historical decisions are stored and queryable")
        print("   2. Can lookup by service name, CVE, or both")
        print("   3. Validates new decisions against historical cases")
        print("   4. Detects regressions (inconsistent decisions)")
        print("   5. Ensures accountability and consistency over time")

        print("\n🎯 Value Proposition:")
        print(
            '   "We\'re the only tool that validates decisions against historical cases."'
        )
        print(
            '   "If we said BLOCK for Log4Shell in 2021, we\'ll say BLOCK for similar CVEs today."'
        )
        print('   "No other tool provides this level of decision consistency."')

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
