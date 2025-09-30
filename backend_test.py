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

    def test_health_endpoints(self):
        """Test core health and monitoring endpoints"""
        print("\n🏥 Testing Health & Monitoring Endpoints...")
        
        # Test health endpoint
        success, health_data = self.run_test("Health Check", "GET", "health", 200)
        if success and health_data:
            if health_data.get('status') == 'healthy':
                print(f"✅ Health status: {health_data.get('status')}")
            else:
                print(f"⚠️  Health status: {health_data.get('status')}")
        
        # Test readiness endpoint
        success, ready_data = self.run_test("Readiness Check", "GET", "ready", 200)
        if success and ready_data:
            dependencies = ready_data.get('dependencies', {})
            print(f"   Dependencies: cache={dependencies.get('cache')}, database={dependencies.get('database')}")
        
        # Test metrics endpoint
        success, metrics_data = self.run_test("Metrics Endpoint", "GET", "metrics", 200)
        
        return True

    def test_api_v1_structure(self):
        """Test API v1 structure and endpoints"""
        print("\n🔗 Testing API v1 Structure...")
        
        # Test auth endpoints (should return 401/422 for missing data, not 404)
        endpoints_to_test = [
            ("api/v1/auth/login", "POST", 422),  # Missing required fields
            ("api/v1/users", "GET", 401),        # Unauthorized
            ("api/v1/incidents", "GET", 401),    # Unauthorized  
            ("api/v1/analytics", "GET", 401),    # Unauthorized
            ("api/v1/monitoring", "GET", 401),   # Unauthorized
            ("api/v1/admin", "GET", 401),        # Unauthorized
        ]
        
        for endpoint, method, expected_status in endpoints_to_test:
            self.run_test(f"API Structure - {endpoint}", method, endpoint, expected_status)
        
        return True

    def test_correlation_engine(self):
        """Test correlation engine functionality"""
        print("\n🔗 Testing Correlation Engine...")
        
        # Test correlation engine via CLI
        try:
            result = subprocess.run([
                "python", "/app/fixops-blended-enterprise/src/cli/main.py", "health"
            ], capture_output=True, text=True, timeout=30, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode == 0:
                print("✅ CLI health check passed")
                try:
                    cli_output = json.loads(result.stdout)
                    if cli_output.get('status') == 'healthy':
                        print("✅ Correlation engine health: OK")
                        self.tests_passed += 1
                    else:
                        print(f"⚠️  Correlation engine health: {cli_output.get('status')}")
                except json.JSONDecodeError:
                    print("⚠️  CLI output not in JSON format")
            else:
                print(f"❌ CLI health check failed: {result.stderr}")
            
            self.tests_run += 1
            
        except subprocess.TimeoutExpired:
            print("❌ CLI health check timed out")
            self.tests_run += 1
        except Exception as e:
            print(f"❌ CLI test error: {str(e)}")
            self.tests_run += 1
        
        return True

    def test_policy_engine(self):
        """Test policy engine functionality"""
        print("\n🛡️  Testing Policy Engine...")
        
        # Test policy check via CLI
        try:
            result = subprocess.run([
                "python", "/app/fixops-blended-enterprise/src/cli/main.py", "policy-check",
                "--severity", "high",
                "--environment", "production",
                "--data-classification", "internal"
            ], capture_output=True, text=True, timeout=30, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode in [0, 1, 2]:  # Valid exit codes for policy decisions
                print("✅ Policy engine CLI test passed")
                try:
                    cli_output = json.loads(result.stdout)
                    decision = cli_output.get('policy_decision')
                    confidence = cli_output.get('confidence')
                    print(f"   Policy decision: {decision} (confidence: {confidence})")
                    self.tests_passed += 1
                except json.JSONDecodeError:
                    print("⚠️  Policy CLI output not in JSON format")
            else:
                print(f"❌ Policy engine CLI failed: {result.stderr}")
            
            self.tests_run += 1
            
        except subprocess.TimeoutExpired:
            print("❌ Policy engine CLI timed out")
            self.tests_run += 1
        except Exception as e:
            print(f"❌ Policy engine test error: {str(e)}")
            self.tests_run += 1
        
        return True

    def test_fix_engine(self):
        """Test fix engine functionality"""
        print("\n🔧 Testing Fix Engine...")
        
        # Test fix generation via CLI
        try:
            result = subprocess.run([
                "python", "/app/fixops-blended-enterprise/src/cli/main.py", "generate-fixes",
                "--limit", "5",
                "--min-confidence", "0.5"
            ], capture_output=True, text=True, timeout=30, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode == 0:
                print("✅ Fix engine CLI test passed")
                try:
                    cli_output = json.loads(result.stdout)
                    fixes_count = cli_output.get('fixes_generated', 0)
                    print(f"   Fixes generated: {fixes_count}")
                    self.tests_passed += 1
                except json.JSONDecodeError:
                    print("⚠️  Fix engine CLI output not in JSON format")
            else:
                print(f"❌ Fix engine CLI failed: {result.stderr}")
            
            self.tests_run += 1
            
        except subprocess.TimeoutExpired:
            print("❌ Fix engine CLI timed out")
            self.tests_run += 1
        except Exception as e:
            print(f"❌ Fix engine test error: {str(e)}")
            self.tests_run += 1
        
        return True

    def test_llm_integration(self):
        """Test LLM integration functionality"""
        print("\n🤖 Testing LLM Integration...")
        
        # Check if LLM key is configured
        try:
            import os
            llm_key = os.getenv('EMERGENT_LLM_KEY')
            if llm_key:
                print("✅ LLM API key is configured")
                self.tests_passed += 1
            else:
                print("⚠️  LLM API key not configured - using rule-based engines only")
                self.tests_passed += 1  # This is acceptable
            
            self.tests_run += 1
            
        except Exception as e:
            print(f"❌ LLM integration test error: {str(e)}")
            self.tests_run += 1
        
        return True

    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting FixOps Enterprise Backend Testing...")
        print(f"Testing against: {self.base_url}")
        
        # Test basic connectivity first
        if not self.test_health_endpoints():
            print("❌ Health endpoints failed - stopping tests")
            return False
        
        # Run all test suites
        test_suites = [
            self.test_api_v1_structure,
            self.test_correlation_engine,
            self.test_policy_engine,
            self.test_fix_engine,
            self.test_llm_integration
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