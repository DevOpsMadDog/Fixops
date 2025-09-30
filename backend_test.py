import requests
import sys
import json
import asyncio
import subprocess
from datetime import datetime

class FixOpsAPITester:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0

    def run_test(self, name, method, endpoint, expected_status, data=None, params=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=10)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=10)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    if isinstance(response_data, list):
                        print(f"   Response: List with {len(response_data)} items")
                    elif isinstance(response_data, dict):
                        print(f"   Response keys: {list(response_data.keys())}")
                except:
                    print(f"   Response: {response.text[:100]}...")
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"   Response: {response.text[:200]}...")

            return success, response.json() if response.status_code < 400 else {}

        except requests.exceptions.Timeout:
            print(f"❌ Failed - Request timeout")
            return False, {}
        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test("Root API", "GET", "api/", 200)

    def test_services_endpoints(self):
        """Test services CRUD operations"""
        print("\n📋 Testing Services Endpoints...")
        
        # Get all services
        success, services_data = self.run_test("Get All Services", "GET", "api/services", 200)
        if not success:
            return False
            
        # Test service creation
        new_service = {
            "name": "test-service",
            "business_capability": "Testing",
            "data_classification": ["internal"],
            "environment": "dev",
            "owner_team": "test-team",
            "owner_email": "test@example.com",
            "internet_facing": False,
            "pci_scope": False
        }
        
        success, created_service = self.run_test("Create Service", "POST", "api/services", 200, new_service)
        if success and created_service.get('id'):
            # Test get specific service
            service_id = created_service['id']
            self.run_test("Get Specific Service", "GET", f"api/services/{service_id}", 200)
        
        return True

    def test_findings_endpoints(self):
        """Test findings endpoints"""
        print("\n🔍 Testing Findings Endpoints...")
        
        # Get all findings
        success, findings_data = self.run_test("Get All Findings", "GET", "api/findings", 200)
        if not success:
            return False
            
        # Test findings with filters
        self.run_test("Get Critical Findings", "GET", "api/findings", 200, params={"severity": "critical"})
        self.run_test("Get SAST Findings", "GET", "api/findings", 200, params={"scanner_type": "sast"})
        
        return True

    def test_cases_endpoints(self):
        """Test correlated cases endpoints"""
        print("\n📊 Testing Cases Endpoints...")
        
        # Get all cases
        success, cases_data = self.run_test("Get All Cases", "GET", "api/cases", 200)
        if not success:
            return False
            
        # If we have cases, test getting a specific one
        if cases_data and len(cases_data) > 0:
            case_id = cases_data[0]['id']
            self.run_test("Get Specific Case", "GET", f"api/cases/{case_id}", 200)
            
            # Test fix suggestions for the case
            self.run_test("Get Fix Suggestions", "GET", f"api/cases/{case_id}/fixes", 200)
        
        return True

    def test_dashboard_endpoints(self):
        """Test dashboard metrics endpoints"""
        print("\n📈 Testing Dashboard Endpoints...")
        
        # Test dashboard metrics
        success, metrics_data = self.run_test("Get Dashboard Metrics", "GET", "api/dashboard/metrics", 200)
        if success and metrics_data:
            # Verify expected metrics are present
            expected_keys = ['total_services', 'total_findings', 'critical_findings', 'high_findings', 
                           'findings_by_scanner', 'services_by_environment', 'mttr_days', 
                           'noise_reduction_percentage', 'policy_decisions']
            missing_keys = [key for key in expected_keys if key not in metrics_data]
            if missing_keys:
                print(f"⚠️  Warning: Missing metrics keys: {missing_keys}")
            else:
                print(f"✅ All expected metrics present")
        
        # Test finding trends
        self.run_test("Get Finding Trends", "GET", "api/dashboard/trends", 200)
        
        return True

    def test_policy_evaluation(self):
        """Test policy evaluation endpoint"""
        print("\n🛡️  Testing Policy Evaluation...")
        
        # Test policy evaluation with different contexts
        test_contexts = [
            {
                "severity": "critical",
                "data_classification": ["pci"],
                "environment": "production",
                "internet_facing": True
            },
            {
                "severity": "high",
                "data_classification": ["pii"],
                "environment": "staging",
                "internet_facing": False
            },
            {
                "severity": "medium",
                "data_classification": ["internal"],
                "environment": "dev",
                "internet_facing": False
            }
        ]
        
        for i, context in enumerate(test_contexts):
            success, policy_result = self.run_test(
                f"Policy Evaluation {i+1}", 
                "POST", 
                "api/policy/evaluate", 
                200, 
                context
            )
            if success and policy_result:
                decisions = policy_result.get('decisions', [])
                print(f"   Policy decisions: {len(decisions)} rules triggered")
        
        return True

    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting FixOps API Testing...")
        print(f"Testing against: {self.base_url}")
        
        # Test basic connectivity
        if not self.test_root_endpoint()[0]:
            print("❌ Root endpoint failed - stopping tests")
            return False
        
        # Run all test suites
        test_suites = [
            self.test_services_endpoints,
            self.test_findings_endpoints,
            self.test_cases_endpoints,
            self.test_dashboard_endpoints,
            self.test_policy_evaluation
        ]
        
        for test_suite in test_suites:
            try:
                test_suite()
            except Exception as e:
                print(f"❌ Test suite failed with error: {str(e)}")
        
        # Print final results
        print(f"\n📊 Final Results:")
        print(f"Tests passed: {self.tests_passed}/{self.tests_run}")
        print(f"Success rate: {(self.tests_passed/self.tests_run)*100:.1f}%")
        
        return self.tests_passed == self.tests_run

def main():
    tester = FixOpsAPITester()
    success = tester.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())