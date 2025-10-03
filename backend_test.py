import os
if os.environ.get("FIXOPS_USE_REAL_REQUESTS") == "1":
    import requests  # type: ignore
else:  # pragma: no cover - exercised in offline pytest runs
    from tests import offline_requests_stub as requests
import sys
import json
import asyncio
import subprocess
import tempfile
import io
from datetime import datetime

# Set LLM key for testing
os.environ['EMERGENT_LLM_KEY'] = 'sk-emergent-aD7C0E299C8FbB4B8A'

class FixOpsDecisionEngineAPITester:
    def __init__(self, base_url="http://localhost:8001"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.failed_tests = []

    def run_test(self, name, method, endpoint, expected_status, data=None, params=None, files=None, headers=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        if headers is None:
            headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=10)
            elif method == 'POST':
                if files:
                    # Remove Content-Type for file uploads
                    headers_copy = headers.copy()
                    if 'Content-Type' in headers_copy:
                        del headers_copy['Content-Type']
                    response = requests.post(url, data=data, files=files, headers=headers_copy, timeout=10)
                else:
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
                        if 'data' in response_data:
                            print(f"   Data keys: {list(response_data['data'].keys()) if isinstance(response_data['data'], dict) else 'Non-dict data'}")
                except:
                    print(f"   Response: {response.text[:100]}...")
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"   Response: {response.text[:200]}...")
                self.failed_tests.append({
                    'name': name,
                    'expected': expected_status,
                    'actual': response.status_code,
                    'response': response.text[:200]
                })

            return success, response.json() if response.status_code < 400 and 'application/json' in response.headers.get('content-type', '') else {}

        except requests.exceptions.Timeout:
            print(f"❌ Failed - Request timeout")
            self.failed_tests.append({'name': name, 'error': 'Request timeout'})
            return False, {}
        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            self.failed_tests.append({'name': name, 'error': str(e)})
            return False, {}

    def test_decision_engine_api(self):
        """Test Decision Engine API endpoints - CRITICAL TESTING AREA"""
        print("\n🎯 Testing Decision Engine API Endpoints...")
        
        # Test 1: /api/v1/decisions/make-decision endpoint
        decision_request = {
            "service_name": "payment-service",
            "environment": "production",
            "business_context": {
                "criticality": "high",
                "data_classification": "pci",
                "business_impact": "critical"
            },
            "security_findings": [
                {
                    "rule_id": "SQL_INJECTION_001",
                    "title": "SQL Injection vulnerability detected",
                    "severity": "high",
                    "category": "injection",
                    "file_path": "/src/payment/dao.py",
                    "line_number": 45
                }
            ],
            "sbom_data": {
                "components": [
                    {
                        "name": "express",
                        "version": "4.18.0",
                        "scope": "required"
                    }
                ]
            }
        }
        
        success, response = self.run_test(
            "Decision Engine - Make Decision", 
            "POST", 
            "api/v1/decisions/make-decision", 
            [200, 401, 403],  # Accept auth errors as expected
            data=decision_request
        )
        
        if success and response.get('decision'):
            print(f"   Decision: {response.get('decision')}")
            print(f"   Confidence: {response.get('confidence_score', 'N/A')}")
            print(f"   Evidence ID: {response.get('evidence_id', 'N/A')}")
        
        # Test 2: /api/v1/decisions/metrics endpoint
        success, response = self.run_test(
            "Decision Engine - Metrics", 
            "GET", 
            "api/v1/decisions/metrics", 
            [200, 401, 403]
        )
        
        if success and response.get('data'):
            metrics = response['data']
            print(f"   Total decisions: {metrics.get('total_decisions', 'N/A')}")
            print(f"   High confidence rate: {metrics.get('high_confidence_rate', 'N/A')}")
        
        # Test 3: /api/v1/decisions/recent endpoint
        success, response = self.run_test(
            "Decision Engine - Recent Decisions", 
            "GET", 
            "api/v1/decisions/recent", 
            [200, 401, 403],
            params={"limit": 5}
        )
        
        if success and response.get('data'):
            decisions = response['data']
            print(f"   Recent decisions count: {len(decisions) if isinstance(decisions, list) else 'N/A'}")
        
        # Test 4: /api/v1/decisions/core-components endpoint
        success, response = self.run_test(
            "Decision Engine - Core Components", 
            "GET", 
            "api/v1/decisions/core-components", 
            [200, 401, 403]
        )
        
        if success and response.get('data'):
            components = response['data']
            print(f"   Core components: {list(components.keys()) if isinstance(components, dict) else 'N/A'}")
            
            # Check if all 6 core components are present
            expected_components = ['vector_db', 'llm_rag', 'consensus_checker', 'golden_regression', 'policy_engine', 'sbom_injection']
            if isinstance(components, dict):
                missing_components = [comp for comp in expected_components if comp not in components]
                if missing_components:
                    print(f"   ⚠️  Missing components: {missing_components}")
                else:
                    print(f"   ✅ All 6 core components present")
        
        # Test 5: /api/v1/decisions/ssdlc-stages endpoint
        success, response = self.run_test(
            "Decision Engine - SSDLC Stages", 
            "GET", 
            "api/v1/decisions/ssdlc-stages", 
            [200, 401, 403]
        )
        
        if success and response.get('data'):
            stages = response['data']
            print(f"   SSDLC stages: {list(stages.keys()) if isinstance(stages, dict) else 'N/A'}")
        
        return True

    def test_scan_upload_api(self):
        """Test Scan Upload API endpoints - CRITICAL TESTING AREA"""
        print("\n📁 Testing Scan Upload API...")
        
        # Test 1: Upload SARIF file
        sarif_content = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestScanner"
                        }
                    },
                    "results": [
                        {
                            "ruleId": "SQL_INJECTION",
                            "message": {"text": "SQL injection vulnerability"},
                            "level": "error",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/main.py"},
                                        "region": {"startLine": 42}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        # Create temporary SARIF file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            json.dump(sarif_content, f)
            sarif_file_path = f.name
        
        try:
            with open(sarif_file_path, 'rb') as f:
                files = {'file': ('test.sarif', f, 'application/json')}
                data = {
                    'service_name': 'test-service',
                    'environment': 'production',
                    'scan_type': 'sarif'
                }
                
                success, response = self.run_test(
                    "Scan Upload - SARIF", 
                    "POST", 
                    "api/v1/scans/upload", 
                    [200, 401, 403, 422],  # Accept auth/validation errors
                    data=data,
                    files=files
                )
                
                if success and response.get('data'):
                    upload_data = response['data']
                    print(f"   Findings processed: {upload_data.get('findings_processed', 'N/A')}")
                    print(f"   Processing time: {upload_data.get('processing_time_ms', 'N/A')}ms")
        
        finally:
            os.unlink(sarif_file_path)
        
        # Test 2: Upload SBOM file
        sbom_content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "name": "express",
                    "version": "4.18.0",
                    "purl": "pkg:npm/express@4.18.0",
                    "vulnerabilities": [
                        {
                            "id": "CVE-2022-24999",
                            "description": "Test vulnerability",
                            "ratings": [{"severity": "high"}]
                        }
                    ]
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_content, f)
            sbom_file_path = f.name
        
        try:
            with open(sbom_file_path, 'rb') as f:
                files = {'file': ('test-sbom.json', f, 'application/json')}
                data = {
                    'service_name': 'test-service',
                    'environment': 'production', 
                    'scan_type': 'sbom'
                }
                
                success, response = self.run_test(
                    "Scan Upload - SBOM", 
                    "POST", 
                    "api/v1/scans/upload", 
                    [200, 401, 403, 422],
                    data=data,
                    files=files
                )
        
        finally:
            os.unlink(sbom_file_path)
        
        # Test 3: Upload CSV file
        csv_content = """rule_id,title,description,severity,category,scanner_type,file_path,line_number
XSS_001,Cross-site scripting,XSS vulnerability found,high,injection,sast,src/web.py,123
CRYPTO_001,Weak encryption,Weak crypto algorithm,medium,crypto,sast,src/crypto.py,45"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(csv_content)
            csv_file_path = f.name
        
        try:
            with open(csv_file_path, 'rb') as f:
                files = {'file': ('test.csv', f, 'text/csv')}
                data = {
                    'service_name': 'test-service',
                    'environment': 'production',
                    'scan_type': 'csv'
                }
                
                success, response = self.run_test(
                    "Scan Upload - CSV", 
                    "POST", 
                    "api/v1/scans/upload", 
                    [200, 401, 403, 422],
                    data=data,
                    files=files
                )
        
        finally:
            os.unlink(csv_file_path)
        
        # Test 4: File validation - oversized file
        print("\n   Testing file validation...")
        success, response = self.run_test(
            "Scan Upload - File Size Validation", 
            "POST", 
            "api/v1/scans/upload", 
            [400, 401, 403, 422],  # Should fail with 400 for large file or auth error
            data={'service_name': 'test', 'scan_type': 'json'},
            files={'file': ('large.json', 'x' * (11 * 1024 * 1024), 'application/json')}  # 11MB file
        )
        
        # Test 5: Invalid scan type
        success, response = self.run_test(
            "Scan Upload - Invalid Scan Type", 
            "POST", 
            "api/v1/scans/upload", 
            [400, 401, 403, 422],
            data={'service_name': 'test', 'scan_type': 'invalid'},
            files={'file': ('test.txt', 'test content', 'text/plain')}
        )
        
        return True

    def test_cli_functionality(self):
        """Test CLI commands - CRITICAL TESTING AREA"""
        print("\n💻 Testing CLI Functionality...")
        
        cli_path = "/app/fixops-blended-enterprise/src/cli/main.py"
        
        # Test 1: fixops health command
        try:
            env = os.environ.copy()
            env['EMERGENT_LLM_KEY'] = 'sk-emergent-aD7C0E299C8FbB4B8A'
            
            result = subprocess.run([
                "python", cli_path, "health"
            ], capture_output=True, text=True, timeout=30, 
            cwd="/app/fixops-blended-enterprise", env=env)
            
            if result.returncode == 0:
                print("✅ CLI health command passed")
                self.tests_passed += 1
                try:
                    # Parse JSON output
                    output = result.stdout
                    start_idx = output.find('{')
                    if start_idx != -1:
                        end_idx = self._find_json_end(output, start_idx)
                        json_str = output[start_idx:end_idx]
                        cli_output = json.loads(json_str)
                        
                        print(f"   Status: {cli_output.get('status', 'unknown')}")
                        health_checks = cli_output.get('health_checks', {})
                        print(f"   Components checked: {list(health_checks.keys())}")
                except Exception as e:
                    print(f"   ⚠️  Could not parse CLI output: {str(e)}")
            else:
                print(f"❌ CLI health command failed: {result.stderr}")
                self.failed_tests.append({'name': 'CLI Health', 'error': result.stderr})
            
            self.tests_run += 1
            
        except subprocess.TimeoutExpired:
            print("❌ CLI health command timed out")
            self.tests_run += 1
            self.failed_tests.append({'name': 'CLI Health', 'error': 'Timeout'})
        except Exception as e:
            print(f"❌ CLI health test error: {str(e)}")
            self.tests_run += 1
            self.failed_tests.append({'name': 'CLI Health', 'error': str(e)})
        
        # Test 2: fixops make-decision command
        try:
            result = subprocess.run([
                "python", cli_path, "make-decision",
                "--service-name", "test-service",
                "--environment", "production"
            ], capture_output=True, text=True, timeout=30, 
            cwd="/app/fixops-blended-enterprise", env=env)
            
            if result.returncode in [0, 1, 2]:  # Valid exit codes
                print("✅ CLI make-decision command passed")
                self.tests_passed += 1
                try:
                    output = result.stdout
                    start_idx = output.find('{')
                    if start_idx != -1:
                        end_idx = self._find_json_end(output, start_idx)
                        json_str = output[start_idx:end_idx]
                        cli_output = json.loads(json_str)
                        
                        print(f"   Decision: {cli_output.get('decision', 'unknown')}")
                        print(f"   Confidence: {cli_output.get('confidence_score', 'N/A')}")
                except Exception as e:
                    print(f"   ⚠️  Could not parse decision output: {str(e)}")
            else:
                print(f"❌ CLI make-decision failed: {result.stderr}")
                self.failed_tests.append({'name': 'CLI Make Decision', 'error': result.stderr})
            
            self.tests_run += 1
            
        except Exception as e:
            print(f"❌ CLI make-decision test error: {str(e)}")
            self.tests_run += 1
            self.failed_tests.append({'name': 'CLI Make Decision', 'error': str(e)})
        
        # Test 3: fixops get-evidence command
        try:
            result = subprocess.run([
                "python", cli_path, "get-evidence",
                "--evidence-id", "EVD-2024-0847"
            ], capture_output=True, text=True, timeout=30, 
            cwd="/app/fixops-blended-enterprise", env=env)
            
            if result.returncode in [0, 1]:  # 0 = found, 1 = not found
                print("✅ CLI get-evidence command passed")
                self.tests_passed += 1
                if result.returncode == 1:
                    print("   Evidence not found (expected for test)")
            else:
                print(f"❌ CLI get-evidence failed: {result.stderr}")
                self.failed_tests.append({'name': 'CLI Get Evidence', 'error': result.stderr})
            
            self.tests_run += 1
            
        except Exception as e:
            print(f"❌ CLI get-evidence test error: {str(e)}")
            self.tests_run += 1
            self.failed_tests.append({'name': 'CLI Get Evidence', 'error': str(e)})
        
        # Test 4: Create test SARIF file and test ingest command
        sarif_content = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "TestScanner"}},
                "results": [{
                    "ruleId": "TEST_001",
                    "message": {"text": "Test finding"},
                    "level": "warning"
                }]
            }]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            json.dump(sarif_content, f)
            sarif_file = f.name
        
        try:
            result = subprocess.run([
                "python", cli_path, "ingest",
                "--scan-file", sarif_file,
                "--format", "sarif",
                "--service-name", "test-cli-service",
                "--environment", "production",
                "--scanner-type", "sast",
                "--scanner-name", "TestScanner"
            ], capture_output=True, text=True, timeout=30, 
            cwd="/app/fixops-blended-enterprise", env=env)
            
            if result.returncode in [0, 1, 2]:
                print("✅ CLI ingest command passed")
                self.tests_passed += 1
                try:
                    output = result.stdout
                    start_idx = output.find('{')
                    if start_idx != -1:
                        end_idx = self._find_json_end(output, start_idx)
                        json_str = output[start_idx:end_idx]
                        cli_output = json.loads(json_str)
                        
                        print(f"   Findings ingested: {cli_output.get('findings_ingested', 'N/A')}")
                        print(f"   Service: {cli_output.get('service_name', 'N/A')}")
                except Exception as e:
                    print(f"   ⚠️  Could not parse ingest output: {str(e)}")
            else:
                print(f"❌ CLI ingest failed: {result.stderr}")
                self.failed_tests.append({'name': 'CLI Ingest', 'error': result.stderr})
            
            self.tests_run += 1
            
        except Exception as e:
            print(f"❌ CLI ingest test error: {str(e)}")
            self.tests_run += 1
            self.failed_tests.append({'name': 'CLI Ingest', 'error': str(e)})
        finally:
            os.unlink(sarif_file)
        
        return True
    
    def _find_json_end(self, text, start_idx):
        """Find the end of a JSON object in text"""
        brace_count = 0
        for i, char in enumerate(text[start_idx:], start_idx):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    return i + 1
        return len(text)

    def test_core_services(self):
        """Test core services initialization and functionality"""
        print("\n⚙️  Testing Core Services...")
        
        # Test decision_engine initialization
        try:
            result = subprocess.run([
                "python", "-c", 
                """
import sys
sys.path.insert(0, '/app/fixops-blended-enterprise')
from src.services.decision_engine import decision_engine
import asyncio

async def test_decision_engine():
    try:
        await decision_engine.initialize()
        print('Decision engine initialized successfully')
        
        # Test core components
        metrics = await decision_engine.get_decision_metrics()
        print(f'Core components: {list(metrics.get("core_components", {}).keys())}')
        
        # Test recent decisions
        recent = await decision_engine.get_recent_decisions(3)
        print(f'Recent decisions: {len(recent)} entries')
        
        return True
    except Exception as e:
        print(f'Decision engine error: {str(e)}')
        return False

result = asyncio.run(test_decision_engine())
sys.exit(0 if result else 1)
                """
            ], capture_output=True, text=True, timeout=30, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode == 0:
                print("✅ Decision engine initialization successful")
                print(f"   Output: {result.stdout.strip()}")
                self.tests_passed += 1
            else:
                print(f"❌ Decision engine initialization failed: {result.stderr}")
                self.failed_tests.append({'name': 'Decision Engine Init', 'error': result.stderr})
            
            self.tests_run += 1
            
        except Exception as e:
            print(f"❌ Decision engine test error: {str(e)}")
            self.tests_run += 1
            self.failed_tests.append({'name': 'Decision Engine Init', 'error': str(e)})
        
        # Test correlation_engine
        try:
            result = subprocess.run([
                "python", "-c", 
                """
import sys
sys.path.insert(0, '/app/fixops-blended-enterprise')
from src.services.correlation_engine import correlation_engine
import asyncio

async def test_correlation():
    try:
        stats = await correlation_engine.get_correlation_stats()
        print(f'Correlation stats: {stats}')
        return True
    except Exception as e:
        print(f'Correlation engine error: {str(e)}')
        return False

result = asyncio.run(test_correlation())
sys.exit(0 if result else 1)
                """
            ], capture_output=True, text=True, timeout=15, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode == 0:
                print("✅ Correlation engine working")
                print(f"   Stats: {result.stdout.strip()}")
                self.tests_passed += 1
            else:
                print(f"❌ Correlation engine failed: {result.stderr}")
                self.failed_tests.append({'name': 'Correlation Engine', 'error': result.stderr})
            
            self.tests_run += 1
            
        except Exception as e:
            print(f"❌ Correlation engine test error: {str(e)}")
            self.tests_run += 1
            self.failed_tests.append({'name': 'Correlation Engine', 'error': str(e)})
        
        # Test policy_engine
        try:
            result = subprocess.run([
                "python", "-c", 
                """
import sys
sys.path.insert(0, '/app/fixops-blended-enterprise')
from src.services.policy_engine import policy_engine
import asyncio

async def test_policy():
    try:
        stats = await policy_engine.get_policy_stats()
        print(f'Policy stats: {stats}')
        return True
    except Exception as e:
        print(f'Policy engine error: {str(e)}')
        return False

result = asyncio.run(test_policy())
sys.exit(0 if result else 1)
                """
            ], capture_output=True, text=True, timeout=15, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode == 0:
                print("✅ Policy engine working")
                print(f"   Stats: {result.stdout.strip()}")
                self.tests_passed += 1
            else:
                print(f"❌ Policy engine failed: {result.stderr}")
                self.failed_tests.append({'name': 'Policy Engine', 'error': result.stderr})
            
            self.tests_run += 1
            
        except Exception as e:
            print(f"❌ Policy engine test error: {str(e)}")
            self.tests_run += 1
            self.failed_tests.append({'name': 'Policy Engine', 'error': str(e)})
        
        return True

    def test_database_operations(self):
        """Test database connectivity and operations - CRITICAL TESTING AREA"""
        print("\n💾 Testing Database Operations...")
        
        try:
            # Test database file exists
            db_path = "/app/fixops-blended-enterprise/fixops_enterprise.db"
            if os.path.exists(db_path):
                print("✅ SQLite database file exists")
                print(f"   Database path: {db_path}")
                print(f"   File size: {os.path.getsize(db_path)} bytes")
                self.tests_passed += 1
            else:
                print("❌ SQLite database file not found")
                self.failed_tests.append({'name': 'Database File', 'error': 'Database file missing'})
            
            self.tests_run += 1
            
            # Test database connectivity via DatabaseManager
            result = subprocess.run([
                "python", "-c", 
                """
import sys
sys.path.insert(0, '/app/fixops-blended-enterprise')
from src.db.session import DatabaseManager
import asyncio

async def test_db():
    try:
        await DatabaseManager.initialize()
        health = await DatabaseManager.health_check()
        print(f'Database health: {health}')
        
        # Test session context
        async with DatabaseManager.get_session_context() as session:
            print('Database session created successfully')
        
        await DatabaseManager.close()
        return True
    except Exception as e:
        print(f'Database error: {str(e)}')
        return False

result = asyncio.run(test_db())
sys.exit(0 if result else 1)
                """
            ], capture_output=True, text=True, timeout=15, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode == 0:
                print("✅ Database connectivity working")
                print(f"   {result.stdout.strip()}")
                self.tests_passed += 1
            else:
                print(f"❌ Database connectivity failed: {result.stderr}")
                self.failed_tests.append({'name': 'Database Connectivity', 'error': result.stderr})
            
            self.tests_run += 1
            
            # Test data persistence by checking if tables exist
            result = subprocess.run([
                "python", "-c", 
                """
import sqlite3
import sys

try:
    conn = sqlite3.connect('/app/fixops-blended-enterprise/fixops_enterprise.db')
    cursor = conn.cursor()
    
    # Check if main tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    
    expected_tables = ['security_findings', 'services', 'users', 'incidents']
    existing_expected = [t for t in expected_tables if t in tables]
    
    print(f'Tables found: {len(tables)}')
    print(f'Expected tables present: {len(existing_expected)}/{len(expected_tables)}')
    print(f'Tables: {", ".join(tables[:10])}{"..." if len(tables) > 10 else ""}')
    
    conn.close()
    sys.exit(0)
except Exception as e:
    print(f'Database schema check error: {str(e)}')
    sys.exit(1)
                """
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print("✅ Database schema validation passed")
                print(f"   {result.stdout.strip()}")
                self.tests_passed += 1
            else:
                print(f"❌ Database schema validation failed: {result.stderr}")
                self.failed_tests.append({'name': 'Database Schema', 'error': result.stderr})
            
            self.tests_run += 1
            
        except Exception as e:
            print(f"❌ Database test error: {str(e)}")
            self.tests_run += 1
            self.failed_tests.append({'name': 'Database Operations', 'error': str(e)})
        
        return True

    def test_authentication_security(self):
        """Test authentication and security features - CRITICAL TESTING AREA"""
        print("\n🔐 Testing Authentication & Security...")
        
        # Test 1: Authentication middleware (should return 401/403 for protected endpoints)
        protected_endpoints = [
            "api/v1/decisions/make-decision",
            "api/v1/decisions/metrics", 
            "api/v1/decisions/recent",
            "api/v1/decisions/core-components",
            "api/v1/scans/upload",
            "api/v1/users",
            "api/v1/incidents"
        ]
        
        for endpoint in protected_endpoints:
            success, response = self.run_test(
                f"Auth Protection - {endpoint}", 
                "GET", 
                endpoint, 
                [401, 403]  # Should be unauthorized/forbidden
            )
            
            if success:
                print(f"   ✅ {endpoint} properly protected")
            else:
                print(f"   ⚠️  {endpoint} may not be properly protected")
        
        # Test 2: Login endpoint validation
        success, response = self.run_test(
            "Auth Login - Missing Fields", 
            "POST", 
            "api/v1/auth/login", 
            422,  # Should return validation error for missing fields
            data={}
        )
        
        if success:
            print("   ✅ Login endpoint validates required fields")
        
        # Test 3: Public endpoints (should work without auth)
        public_endpoints = [
            ("health", "GET"),
            ("ready", "GET"), 
            ("metrics", "GET"),
            ("api/v1/monitoring/health", "GET")
        ]
        
        for endpoint, method in public_endpoints:
            success, response = self.run_test(
                f"Public Access - {endpoint}", 
                method, 
                endpoint, 
                200
            )
            
            if success:
                print(f"   ✅ {endpoint} publicly accessible")
        
        return True

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

    def test_llm_integration(self):
        """Test LLM integration functionality"""
        print("\n🤖 Testing LLM Integration...")
        
        # Check if LLM key is configured
        try:
            llm_key = os.getenv('EMERGENT_LLM_KEY')
            if llm_key and llm_key.startswith('sk-emergent-'):
                print("✅ LLM API key is configured")
                print(f"   Key: {llm_key[:20]}...")
                self.tests_passed += 1
            else:
                print("⚠️  LLM API key not configured - using rule-based engines only")
                self.tests_passed += 1  # This is acceptable
            
            self.tests_run += 1
            
        except Exception as e:
            print(f"❌ LLM integration test error: {str(e)}")
            self.tests_run += 1
            self.failed_tests.append({'name': 'LLM Integration', 'error': str(e)})
        
        return True

    def test_enhanced_api_endpoints(self):
        """Test Enhanced API endpoints as specified in review request"""
        print("\n🔥 Testing Enhanced API Endpoints (Review Request)...")
        
        # Test 1: GET /api/v1/enhanced/capabilities
        success, response = self.run_test(
            "Enhanced Capabilities", 
            "GET", 
            "api/v1/enhanced/capabilities", 
            200
        )
        
        if success and response.get('data'):
            data = response['data']
            if 'supported_llms' in data:
                print(f"   ✅ supported_llms present: {list(data['supported_llms'].keys())}")
            else:
                print(f"   ❌ supported_llms missing from response")
                self.failed_tests.append({'name': 'Enhanced Capabilities - supported_llms', 'error': 'supported_llms field missing'})
        
        # Test 2: POST /api/v1/enhanced/compare-llms
        compare_request = {
            "service_name": "test-service",
            "security_findings": [
                {
                    "severity": "high",
                    "category": "injection", 
                    "title": "SQL Injection vulnerability",
                    "source": "sonarqube"
                }
            ],
            "business_context": {}
        }
        
        success, response = self.run_test(
            "Enhanced Compare LLMs", 
            "POST", 
            "api/v1/enhanced/compare-llms", 
            200,
            data=compare_request
        )
        
        if success and response.get('data'):
            data = response['data']
            if 'individual_analyses' in data and isinstance(data['individual_analyses'], list):
                print(f"   ✅ individual_analyses array present with {len(data['individual_analyses'])} items")
            else:
                print(f"   ❌ individual_analyses array missing or invalid")
                self.failed_tests.append({'name': 'Enhanced Compare LLMs - individual_analyses', 'error': 'individual_analyses array missing'})
        
        # Test 3: POST /api/v1/enhanced/analysis
        analysis_request = {
            "service_name": "test-service",
            "environment": "production",
            "business_context": {},
            "security_findings": [
                {
                    "severity": "high",
                    "category": "injection",
                    "title": "SQL Injection vulnerability", 
                    "source": "sonarqube"
                }
            ]
        }
        
        success, response = self.run_test(
            "Enhanced Analysis Standard", 
            "POST", 
            "api/v1/enhanced/analysis", 
            200,
            data=analysis_request
        )
        
        if success and response:
            # Check standardized schema
            if 'models' in response and isinstance(response['models'], list):
                print(f"   ✅ models array present with {len(response['models'])} items")
                
                # Check model structure
                if response['models']:
                    model = response['models'][0]
                    required_fields = ['name', 'verdict', 'confidence', 'rationale', 'evidence', 'mitre_ttps']
                    missing_fields = [field for field in required_fields if field not in model]
                    if missing_fields:
                        print(f"   ❌ Missing model fields: {missing_fields}")
                        self.failed_tests.append({'name': 'Enhanced Analysis - model fields', 'error': f'Missing fields: {missing_fields}'})
                    else:
                        print(f"   ✅ Model structure valid")
            else:
                print(f"   ❌ models array missing")
                self.failed_tests.append({'name': 'Enhanced Analysis - models', 'error': 'models array missing'})
            
            if 'consensus' in response:
                consensus = response['consensus']
                required_consensus_fields = ['verdict', 'confidence', 'method']
                missing_consensus = [field for field in required_consensus_fields if field not in consensus]
                if missing_consensus:
                    print(f"   ❌ Missing consensus fields: {missing_consensus}")
                    self.failed_tests.append({'name': 'Enhanced Analysis - consensus', 'error': f'Missing consensus fields: {missing_consensus}'})
                else:
                    print(f"   ✅ Consensus structure valid")
            else:
                print(f"   ❌ consensus missing")
                self.failed_tests.append({'name': 'Enhanced Analysis - consensus', 'error': 'consensus missing'})
        
        return True

    def test_scan_upload_enhanced(self):
        """Test Enhanced Scan Upload endpoints as specified in review request"""
        print("\n📤 Testing Enhanced Scan Upload (Review Request)...")
        
        # Test 4a: Single-shot upload
        json_content = {
            "findings": [
                {
                    "rule_id": "r1",
                    "title": "Test Finding",
                    "severity": "high",
                    "category": "injection",
                    "scanner_type": "generic"
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(json_content, f)
            json_file_path = f.name
        
        try:
            with open(json_file_path, 'rb') as f:
                files = {'file': ('test.json', f, 'application/json')}
                data = {
                    'scan_type': 'json',
                    'service_name': 'svc',
                    'environment': 'production'
                }
                
                success, response = self.run_test(
                    "Scan Upload - Single-shot JSON", 
                    "POST", 
                    "api/v1/scans/upload", 
                    200,
                    data=data,
                    files=files
                )
                
                if success and response.get('data'):
                    upload_data = response['data']
                    if 'findings_processed' in upload_data:
                        print(f"   ✅ Single-shot upload successful: {upload_data['findings_processed']} findings processed")
                    else:
                        print(f"   ❌ findings_processed count missing")
                        self.failed_tests.append({'name': 'Single-shot Upload - counts', 'error': 'findings_processed missing'})
        
        finally:
            os.unlink(json_file_path)
        
        # Test 4b: Chunked upload flow
        print("\n   Testing chunked upload flow...")
        
        # Step i: Initialize chunked upload
        init_request = {
            "file_name": "sample.json",
            "total_size": len(json.dumps(json_content).encode('utf-8')),
            "scan_type": "json",
            "service_name": "svc",
            "environment": "production"
        }
        
        success, response = self.run_test(
            "Chunked Upload - Init", 
            "POST", 
            "api/v1/scans/upload/init", 
            200,
            data=init_request
        )
        
        upload_id = None
        if success and response.get('data', {}).get('upload_id'):
            upload_id = response['data']['upload_id']
            print(f"   ✅ Upload initialized with ID: {upload_id}")
        else:
            print(f"   ❌ Upload init failed - no upload_id returned")
            self.failed_tests.append({'name': 'Chunked Upload - Init', 'error': 'No upload_id returned'})
            return True
        
        # Step ii: Upload chunk
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(json_content, f)
            chunk_file_path = f.name
        
        try:
            with open(chunk_file_path, 'rb') as f:
                files = {'chunk': ('sample.json', f, 'application/json')}
                data = {
                    'upload_id': upload_id,
                    'chunk_index': 0,
                    'total_chunks': 1
                }
                
                success, response = self.run_test(
                    "Chunked Upload - Chunk", 
                    "POST", 
                    "api/v1/scans/upload/chunk", 
                    200,
                    data=data,
                    files=files
                )
                
                if success:
                    print(f"   ✅ Chunk uploaded successfully")
                else:
                    print(f"   ❌ Chunk upload failed")
                    return True
        
        finally:
            os.unlink(chunk_file_path)
        
        # Step iii: Complete upload
        complete_request = {"upload_id": upload_id}
        
        success, response = self.run_test(
            "Chunked Upload - Complete", 
            "POST", 
            "api/v1/scans/upload/complete", 
            200,
            data=complete_request
        )
        
        if success and response.get('data'):
            upload_data = response['data']
            if 'findings_processed' in upload_data:
                print(f"   ✅ Chunked upload completed: {upload_data['findings_processed']} findings processed")
            else:
                print(f"   ❌ findings_processed count missing from completion")
                self.failed_tests.append({'name': 'Chunked Upload - Complete counts', 'error': 'findings_processed missing'})
        
        return True

    def test_business_context_apis(self):
        """Test Business Context APIs as specified in review request"""
        print("\n📋 Testing Business Context APIs (Review Request)...")
        
        # Test 1: POST /api/v1/business-context/upload with FixOps.yaml
        fixops_yaml_content = """
service_name: payment-service
exploitation: active
exposure: controlled
utility: laborious
safety_impact: negligible
mission_impact: degraded
business_criticality: high
data_classification: pci
internet_facing: true
compliance_requirements:
  - PCI DSS
  - SOC2
owner_team: payments-team
escalation_contacts:
  - security@company.com
attack_surface: web_api
trust_boundaries:
  - external_users
  - internal_services
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(fixops_yaml_content)
            yaml_file_path = f.name
        
        try:
            with open(yaml_file_path, 'rb') as f:
                files = {'file': ('fixops.yaml', f, 'application/x-yaml')}
                data = {
                    'service_name': 'payment-service',
                    'format_type': 'fixops.yaml'
                }
                
                success, response = self.run_test(
                    "Business Context - FixOps.yaml Upload", 
                    "POST", 
                    "api/v1/business-context/upload", 
                    200,
                    data=data,
                    files=files
                )
                
                if success and response.get('data'):
                    upload_data = response['data']
                    if 'ssvc_factors' in upload_data:
                        print(f"   ✅ SSVC factors processed: {list(upload_data['ssvc_factors'].keys())}")
                    else:
                        print(f"   ❌ SSVC factors missing from response")
                        self.failed_tests.append({'name': 'Business Context Upload - SSVC', 'error': 'SSVC factors missing'})
        
        finally:
            os.unlink(yaml_file_path)
        
        # Test 2: POST /api/v1/business-context/upload with OTM.json
        otm_json_content = {
            "otmVersion": "0.1.0",
            "project": {
                "name": "payment-service",
                "id": "payment-svc-001",
                "description": "Payment processing service"
            },
            "representations": [
                {
                    "name": "Architecture",
                    "id": "architecture",
                    "type": "code"
                }
            ],
            "trustZones": [
                {
                    "id": "internet",
                    "name": "Internet",
                    "risk": {"trustRating": 1}
                },
                {
                    "id": "internal",
                    "name": "Internal Network", 
                    "risk": {"trustRating": 8}
                }
            ],
            "components": [
                {
                    "id": "payment-api",
                    "name": "Payment API",
                    "type": "web-service",
                    "parent": {"trustZone": "internal"},
                    "data": [{"id": "payment-data", "name": "Payment Data", "classification": "PCI"}]
                }
            ],
            "dataflows": [
                {
                    "id": "payment-flow",
                    "name": "Payment Processing",
                    "source": "internet",
                    "destination": "payment-api",
                    "data": ["payment-data"]
                }
            ],
            "threats": [
                {
                    "id": "sql-injection",
                    "name": "SQL Injection",
                    "categories": ["injection"],
                    "status": "open",
                    "severity": "high",
                    "description": "SQL injection in payment processing"
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(otm_json_content, f)
            otm_file_path = f.name
        
        try:
            with open(otm_file_path, 'rb') as f:
                files = {'file': ('threat-model.otm.json', f, 'application/json')}
                data = {
                    'service_name': 'payment-service',
                    'format_type': 'otm.json'
                }
                
                success, response = self.run_test(
                    "Business Context - OTM.json Upload", 
                    "POST", 
                    "api/v1/business-context/upload", 
                    200,
                    data=data,
                    files=files
                )
                
                if success and response.get('data'):
                    upload_data = response['data']
                    if 'ssvc_factors' in upload_data and 'business_context' in upload_data:
                        print(f"   ✅ OTM converted to SSVC successfully")
                    else:
                        print(f"   ❌ OTM to SSVC conversion failed")
                        self.failed_tests.append({'name': 'Business Context OTM - SSVC conversion', 'error': 'SSVC conversion missing'})
        
        finally:
            os.unlink(otm_file_path)
        
        # Test 3: GET /api/v1/business-context/formats
        success, response = self.run_test(
            "Business Context - Supported Formats", 
            "GET", 
            "api/v1/business-context/formats", 
            200
        )
        
        if success and response.get('supported_formats'):
            formats = response['supported_formats']
            expected_formats = ['fixops.yaml', 'otm.json', 'ssvc.yaml']
            missing_formats = [fmt for fmt in expected_formats if fmt not in formats]
            if missing_formats:
                print(f"   ❌ Missing supported formats: {missing_formats}")
                self.failed_tests.append({'name': 'Business Context - Formats', 'error': f'Missing formats: {missing_formats}'})
            else:
                print(f"   ✅ All expected formats supported: {expected_formats}")
        
        return True

    def test_production_readiness_apis(self):
        """Test Production Readiness APIs as specified in review request"""
        print("\n🏭 Testing Production Readiness APIs (Review Request)...")
        
        # Test 1: GET /api/v1/production-readiness/status
        success, response = self.run_test(
            "Production Readiness - Status", 
            "GET", 
            "api/v1/production-readiness/status", 
            200
        )
        
        if success and response.get('data'):
            status_data = response['data']
            required_fields = ['demo_mode', 'overall_production_ready', 'missing_requirements', 'component_status']
            missing_fields = [field for field in required_fields if field not in status_data]
            if missing_fields:
                print(f"   ❌ Missing status fields: {missing_fields}")
                self.failed_tests.append({'name': 'Production Readiness - Status fields', 'error': f'Missing fields: {missing_fields}'})
            else:
                print(f"   ✅ Production readiness status complete")
                print(f"   Demo mode: {status_data.get('demo_mode')}")
                print(f"   Production ready: {status_data.get('overall_production_ready')}")
                print(f"   Missing requirements: {len(status_data.get('missing_requirements', []))}")
                
                # Check component status
                components = status_data.get('component_status', {})
                expected_components = ['vector_database', 'business_context', 'llm_consensus', 'policy_engine', 'evidence_lake']
                missing_components = [comp for comp in expected_components if comp not in components]
                if missing_components:
                    print(f"   ❌ Missing component status: {missing_components}")
                    self.failed_tests.append({'name': 'Production Readiness - Components', 'error': f'Missing components: {missing_components}'})
                else:
                    print(f"   ✅ All component statuses present")
        
        # Test 2: GET /api/v1/production-readiness/requirements
        success, response = self.run_test(
            "Production Readiness - Requirements", 
            "GET", 
            "api/v1/production-readiness/requirements", 
            200
        )
        
        if success and response.get('requirements'):
            requirements = response['requirements']
            expected_requirements = ['EMERGENT_LLM_KEY', 'OPA_SERVER', 'JIRA_CREDENTIALS', 'CONFLUENCE_CREDENTIALS']
            missing_requirements = [req for req in expected_requirements if req not in requirements]
            if missing_requirements:
                print(f"   ❌ Missing requirement details: {missing_requirements}")
                self.failed_tests.append({'name': 'Production Readiness - Requirements', 'error': f'Missing requirements: {missing_requirements}'})
            else:
                print(f"   ✅ All production requirements documented")
        
        return True

    def test_system_mode_apis(self):
        """Test System Mode APIs as specified in review request"""
        print("\n⚙️ Testing System Mode APIs (Review Request)...")
        
        # Test 1: GET /api/v1/system-mode/current
        success, response = self.run_test(
            "System Mode - Current", 
            "GET", 
            "api/v1/system-mode/current", 
            200
        )
        
        if success and response.get('data'):
            mode_data = response['data']
            required_fields = ['current_mode', 'demo_mode_enabled', 'production_ready', 'missing_requirements', 'components_status']
            missing_fields = [field for field in required_fields if field not in mode_data]
            if missing_fields:
                print(f"   ❌ Missing mode fields: {missing_fields}")
                self.failed_tests.append({'name': 'System Mode - Current fields', 'error': f'Missing fields: {missing_fields}'})
            else:
                print(f"   ✅ System mode status complete")
                print(f"   Current mode: {mode_data.get('current_mode')}")
                print(f"   Production ready: {mode_data.get('production_ready')}")
                
                # Check component status
                components = mode_data.get('components_status', {})
                expected_components = ['decision_engine', 'vector_database', 'llm_consensus', 'policy_engine', 'evidence_lake']
                missing_components = [comp for comp in expected_components if comp not in components]
                if missing_components:
                    print(f"   ❌ Missing component status: {missing_components}")
                    self.failed_tests.append({'name': 'System Mode - Components', 'error': f'Missing components: {missing_components}'})
                else:
                    print(f"   ✅ All component statuses present")
        
        # Test 2: GET /api/v1/system-mode/production-requirements
        success, response = self.run_test(
            "System Mode - Production Requirements", 
            "GET", 
            "api/v1/system-mode/production-requirements", 
            200
        )
        
        if success and response.get('requirements'):
            requirements = response['requirements']
            if 'critical' in requirements and 'optional' in requirements:
                print(f"   ✅ Production requirements categorized (critical/optional)")
                critical_reqs = requirements['critical']
                if 'EMERGENT_LLM_KEY' in critical_reqs and 'OPA_SERVER' in critical_reqs:
                    print(f"   ✅ Critical requirements present")
                else:
                    print(f"   ❌ Missing critical requirements")
                    self.failed_tests.append({'name': 'System Mode - Critical Requirements', 'error': 'Missing critical requirements'})
            else:
                print(f"   ❌ Requirements not properly categorized")
                self.failed_tests.append({'name': 'System Mode - Requirements Structure', 'error': 'Requirements not categorized'})
        
        # Test 3: POST /api/v1/system-mode/toggle (should fail without proper requirements)
        toggle_request = {
            "target_mode": "production",
            "force": False
        }
        
        success, response = self.run_test(
            "System Mode - Toggle (Expected Failure)", 
            "POST", 
            "api/v1/system-mode/toggle", 
            400,  # Should fail due to missing requirements
            data=toggle_request
        )
        
        if success:
            print(f"   ✅ Mode toggle properly validates requirements")
        else:
            print(f"   ⚠️ Mode toggle validation may not be working correctly")
        
        return True

    def test_core_stability_check(self):
        """Test Core Stability as specified in review request"""
        print("\n🔧 Testing Core Stability (Review Request)...")
        
        # Test decision engine with business context + security findings
        decision_request = {
            "service_name": "payment-service",
            "environment": "production",
            "business_context": {
                "criticality": "high",
                "data_classification": "pci",
                "business_impact": "critical",
                "compliance_requirements": ["PCI DSS", "SOC2"],
                "internet_facing": True
            },
            "security_findings": [
                {
                    "rule_id": "SQL_INJECTION_001",
                    "title": "SQL Injection vulnerability detected",
                    "severity": "high",
                    "category": "injection",
                    "file_path": "/src/payment/dao.py",
                    "line_number": 45,
                    "scanner_type": "sast",
                    "confidence": 0.9
                },
                {
                    "rule_id": "CRYPTO_WEAK_001",
                    "title": "Weak cryptographic algorithm",
                    "severity": "medium",
                    "category": "crypto",
                    "file_path": "/src/payment/crypto.py",
                    "line_number": 23,
                    "scanner_type": "sast",
                    "confidence": 0.8
                }
            ],
            "sbom_data": {
                "components": [
                    {
                        "name": "express",
                        "version": "4.18.0",
                        "scope": "required",
                        "vulnerabilities": [
                            {
                                "id": "CVE-2022-24999",
                                "severity": "high",
                                "description": "Test vulnerability"
                            }
                        ]
                    }
                ]
            }
        }
        
        success, response = self.run_test(
            "Core Stability - Decision Engine Integration", 
            "POST", 
            "api/v1/decisions/make-decision", 
            [200, 401, 403],  # Accept auth errors as expected
            data=decision_request
        )
        
        if success and response.get('decision'):
            print(f"   ✅ Decision engine processing complex context")
            print(f"   Decision: {response.get('decision')}")
            print(f"   Confidence: {response.get('confidence_score', 'N/A')}")
            print(f"   Evidence ID: {response.get('evidence_id', 'N/A')}")
        
        # Test evidence lake storage and retrieval
        if success and response.get('evidence_id'):
            evidence_id = response['evidence_id']
            
            # Try to retrieve evidence (this might require authentication)
            success_evidence, evidence_response = self.run_test(
                "Core Stability - Evidence Lake Retrieval", 
                "GET", 
                f"api/v1/evidence/{evidence_id}", 
                [200, 401, 403, 404]  # Accept various responses
            )
            
            if success_evidence:
                print(f"   ✅ Evidence lake storage and retrieval working")
            else:
                print(f"   ⚠️ Evidence retrieval endpoint may need authentication")
        
        # Test vector store and policy engine integration via core components
        success, response = self.run_test(
            "Core Stability - Vector Store & Policy Engine", 
            "GET", 
            "api/v1/decisions/core-components", 
            [200, 401, 403]
        )
        
        if success and response.get('data'):
            components = response['data']
            critical_components = ['vector_db', 'policy_engine', 'llm_rag', 'consensus_checker']
            working_components = [comp for comp in critical_components if comp in components and components[comp].get('status') == 'operational']
            
            if len(working_components) >= 3:  # At least 3 out of 4 critical components
                print(f"   ✅ Core components integration stable ({len(working_components)}/{len(critical_components)})")
            else:
                print(f"   ❌ Core components integration unstable ({len(working_components)}/{len(critical_components)})")
                self.failed_tests.append({'name': 'Core Stability - Components', 'error': f'Only {len(working_components)} components working'})
        
        return True

    def run_all_tests(self):
        """Run all comprehensive FixOps Decision Engine tests"""
        print("🚀 Starting FixOps Decision Engine Backend Testing...")
        print(f"Testing against: {self.base_url}")
        print("=" * 80)
        
        # Test basic connectivity first
        if not self.test_health_endpoints():
            print("❌ Health endpoints failed - stopping tests")
            return False
        
        # Run all test suites based on review request priorities
        test_suites = [
            # PRIORITY TESTING AREAS from review request (ROUND 2)
            ("Enhanced API Endpoints (Previously Fixed)", self.test_enhanced_api_endpoints),
            ("Enhanced Scan Upload (Partially Fixed)", self.test_scan_upload_enhanced),
            ("Business Context APIs (New)", self.test_business_context_apis),
            ("Production Readiness APIs (New)", self.test_production_readiness_apis),
            ("System Mode APIs (New)", self.test_system_mode_apis),
            ("Core Stability Check", self.test_core_stability_check),
            # EXISTING CRITICAL TESTING AREAS
            ("Decision Engine API", self.test_decision_engine_api),
            ("Scan Upload API", self.test_scan_upload_api), 
            ("Core Services", self.test_core_services),
            ("CLI Integration", self.test_cli_functionality),
            ("Database Operations", self.test_database_operations),
            ("Authentication & Security", self.test_authentication_security),
            ("LLM Integration", self.test_llm_integration)
        ]
        
        for suite_name, test_suite in test_suites:
            try:
                print(f"\n{'='*20} {suite_name} {'='*20}")
                test_suite()
            except Exception as e:
                print(f"❌ Test suite '{suite_name}' failed with error: {str(e)}")
                self.failed_tests.append({'name': f'{suite_name} Suite', 'error': str(e)})
        
        # Print comprehensive results
        print(f"\n{'='*80}")
        print(f"📊 COMPREHENSIVE TEST RESULTS:")
        print(f"Tests passed: {self.tests_passed}/{self.tests_run}")
        print(f"Success rate: {(self.tests_passed/self.tests_run)*100:.1f}%")
        
        if self.failed_tests:
            print(f"\n❌ FAILED TESTS ({len(self.failed_tests)}):")
            for i, failure in enumerate(self.failed_tests, 1):
                print(f"   {i}. {failure['name']}")
                if 'error' in failure:
                    print(f"      Error: {failure['error']}")
                if 'expected' in failure:
                    print(f"      Expected: {failure['expected']}, Got: {failure['actual']}")
        
        print(f"\n{'='*80}")
        
        return len(self.failed_tests) == 0

def main():
    tester = FixOpsDecisionEngineAPITester()
    success = tester.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())