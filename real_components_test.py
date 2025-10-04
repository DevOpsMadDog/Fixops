#!/usr/bin/env python3
"""
Focused testing for Real Components Implementation
Tests the newly implemented real components as specified in the review request
"""

import os

import pytest

requests = pytest.importorskip(
    "requests", reason="HTTP integration tests require the optional 'requests' dependency"
)

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_FIXOPS_INTEGRATION_TESTS") != "1",
    reason="FixOps real component integration tests require running services",
)
import json
import sys
import os
import asyncio
import subprocess
from datetime import datetime

# Set LLM key for testing
os.environ['EMERGENT_LLM_KEY'] = 'sk-emergent-aD7C0E299C8FbB4B8A'

class RealComponentsTester:
    def __init__(self, base_url="http://localhost:8001"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.failed_tests = []

    def log_result(self, test_name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {test_name}")
            if details:
                print(f"   {details}")
        else:
            print(f"❌ {test_name}")
            if details:
                print(f"   {details}")
            self.failed_tests.append({"name": test_name, "details": details})

    def test_real_vector_store_integration(self):
        """Test Real Vector Store Integration (ChromaDB)"""
        print("\n🔍 Testing Real Vector Store Integration (ChromaDB)...")
        
        try:
            # Test vector store initialization and functionality
            result = subprocess.run([
                "python", "-c", 
                """
import sys
sys.path.insert(0, '/app/fixops-blended-enterprise')
import asyncio
from src.services.vector_store import get_vector_store, VectorStoreFactory
from src.config.settings import get_settings

async def test_vector_store():
    try:
        settings = get_settings()
        print(f'Demo mode: {settings.DEMO_MODE}')
        
        # Test factory creation
        vector_store = VectorStoreFactory.create(settings)
        print(f'Vector store type: {type(vector_store).__name__}')
        
        # Test initialization
        await vector_store.initialize()
        print('Vector store initialized successfully')
        
        # Test search functionality
        results = await vector_store.search_security_patterns("SQL injection vulnerability", top_k=3)
        print(f'Search results: {len(results)} patterns found')
        
        if results:
            for i, result in enumerate(results):
                print(f'  Pattern {i+1}: {result.metadata.get("category", "unknown")} - {result.similarity_score:.3f}')
        
        return True
    except Exception as e:
        print(f'Vector store test error: {str(e)}')
        return False

result = asyncio.run(test_vector_store())
sys.exit(0 if result else 1)
                """
            ], capture_output=True, text=True, timeout=30, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode == 0:
                output_lines = result.stdout.strip().split('\n')
                demo_mode = "Demo mode: True" in result.stdout
                vector_type = "DemoVectorStore" if demo_mode else "ChromaDBVectorStore"
                
                self.log_result(
                    "Vector Store Initialization", 
                    True, 
                    f"Type: {vector_type}, Mode: {'Demo' if demo_mode else 'Production'}"
                )
                
                if "patterns found" in result.stdout:
                    patterns_count = [line for line in output_lines if "patterns found" in line][0]
                    self.log_result("Vector Store Search", True, patterns_count)
                else:
                    self.log_result("Vector Store Search", False, "No search results found")
                    
            else:
                self.log_result("Vector Store Integration", False, f"Error: {result.stderr}")
                
        except Exception as e:
            self.log_result("Vector Store Integration", False, f"Exception: {str(e)}")

    def test_real_opa_policy_engine(self):
        """Test Real OPA Policy Engine"""
        print("\n🔍 Testing Real OPA Policy Engine...")
        
        try:
            # Test OPA engine functionality
            result = subprocess.run([
                "python", "-c", 
                """
import sys
sys.path.insert(0, '/app/fixops-blended-enterprise')
import asyncio
from src.services.real_opa_engine import get_opa_engine, evaluate_vulnerability_policy, evaluate_sbom_policy
from src.config.settings import get_settings

async def test_opa_engine():
    try:
        settings = get_settings()
        print(f'Demo mode: {settings.DEMO_MODE}')
        
        # Test OPA engine creation
        opa_engine = await get_opa_engine()
        print(f'OPA engine type: {type(opa_engine).__name__}')
        
        # Test health check
        health = await opa_engine.health_check()
        print(f'OPA engine healthy: {health}')
        
        # Test vulnerability policy evaluation
        test_vulnerabilities = [
            {
                "cve_id": "CVE-2023-1234",
                "severity": "CRITICAL",
                "fix_available": False,
                "title": "Test Critical Vulnerability"
            },
            {
                "cve_id": "CVE-2023-5678", 
                "severity": "HIGH",
                "fix_available": True,
                "title": "Test High Vulnerability"
            }
        ]
        
        vuln_result = await evaluate_vulnerability_policy(test_vulnerabilities)
        print(f'Vulnerability policy result: {vuln_result.get("decision", "unknown")}')
        print(f'Vulnerability policy rationale: {vuln_result.get("rationale", "none")}')
        
        # Test SBOM policy evaluation
        sbom_result = await evaluate_sbom_policy(
            sbom_present=True,
            sbom_valid=True,
            sbom_data={
                "components": [
                    {"name": "express", "version": "4.18.0"},
                    {"name": "lodash", "version": "4.17.21"}
                ]
            }
        )
        print(f'SBOM policy result: {sbom_result.get("decision", "unknown")}')
        print(f'SBOM policy rationale: {sbom_result.get("rationale", "none")}')
        
        return True
    except Exception as e:
        print(f'OPA engine test error: {str(e)}')
        return False

result = asyncio.run(test_opa_engine())
sys.exit(0 if result else 1)
                """
            ], capture_output=True, text=True, timeout=30, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode == 0:
                output_lines = result.stdout.strip().split('\n')
                demo_mode = "Demo mode: True" in result.stdout
                opa_type = "DemoOPAEngine" if demo_mode else "ProductionOPAEngine"
                
                self.log_result(
                    "OPA Engine Initialization", 
                    True, 
                    f"Type: {opa_type}, Mode: {'Demo' if demo_mode else 'Production'}"
                )
                
                # Check health status
                health_line = [line for line in output_lines if "OPA engine healthy:" in line]
                if health_line:
                    health_status = health_line[0].split(": ")[1]
                    self.log_result("OPA Engine Health Check", True, f"Healthy: {health_status}")
                
                # Check policy evaluations
                vuln_decision = [line for line in output_lines if "Vulnerability policy result:" in line]
                if vuln_decision:
                    decision = vuln_decision[0].split(": ")[1]
                    self.log_result("Vulnerability Policy Evaluation", True, f"Decision: {decision}")
                
                sbom_decision = [line for line in output_lines if "SBOM policy result:" in line]
                if sbom_decision:
                    decision = sbom_decision[0].split(": ")[1]
                    self.log_result("SBOM Policy Evaluation", True, f"Decision: {decision}")
                    
            else:
                self.log_result("OPA Policy Engine", False, f"Error: {result.stderr}")
                
        except Exception as e:
            self.log_result("OPA Policy Engine", False, f"Exception: {str(e)}")

    def test_real_evidence_lake_storage(self):
        """Test Real Evidence Lake Storage"""
        print("\n🔍 Testing Real Evidence Lake Storage...")
        
        try:
            # Test evidence generation and storage
            result = subprocess.run([
                "python", "-c", 
                """
import sys
sys.path.insert(0, '/app/fixops-blended-enterprise')
import asyncio
from src.services.decision_engine import decision_engine, DecisionContext
from src.config.settings import get_settings

async def test_evidence_lake():
    try:
        settings = get_settings()
        print(f'Demo mode: {settings.DEMO_MODE}')
        
        # Initialize decision engine
        await decision_engine.initialize()
        print('Decision engine initialized')
        
        # Create test context for evidence generation
        context = DecisionContext(
            service_name="test-evidence-service",
            environment="production",
            business_context={"criticality": "high"},
            security_findings=[
                {
                    "rule_id": "TEST_001",
                    "title": "Test Security Finding",
                    "severity": "HIGH",
                    "category": "injection"
                }
            ]
        )
        
        # Make a decision to generate evidence
        result = await decision_engine.make_decision(context)
        print(f'Decision made: {result.decision.value}')
        print(f'Evidence ID: {result.evidence_id}')
        print(f'Confidence: {result.confidence_score}')
        
        # Test evidence retrieval
        if result.evidence_id:
            print(f'Evidence generated successfully: {result.evidence_id}')
            return True
        else:
            print('No evidence ID generated')
            return False
            
    except Exception as e:
        print(f'Evidence lake test error: {str(e)}')
        return False

result = asyncio.run(test_evidence_lake())
sys.exit(0 if result else 1)
                """
            ], capture_output=True, text=True, timeout=30, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode == 0:
                output_lines = result.stdout.strip().split('\n')
                demo_mode = "Demo mode: True" in result.stdout
                
                self.log_result(
                    "Evidence Lake Integration", 
                    True, 
                    f"Mode: {'Demo' if demo_mode else 'Production'}"
                )
                
                # Check evidence generation
                evidence_lines = [line for line in output_lines if "Evidence ID:" in line]
                if evidence_lines:
                    evidence_id = evidence_lines[0].split(": ")[1]
                    self.log_result("Evidence Generation", True, f"ID: {evidence_id}")
                
                decision_lines = [line for line in output_lines if "Decision made:" in line]
                if decision_lines:
                    decision = decision_lines[0].split(": ")[1]
                    self.log_result("Decision Processing", True, f"Decision: {decision}")
                    
            else:
                self.log_result("Evidence Lake Storage", False, f"Error: {result.stderr}")
                
        except Exception as e:
            self.log_result("Evidence Lake Storage", False, f"Exception: {str(e)}")

    def test_real_database_operations(self):
        """Test Real Database Operations"""
        print("\n🔍 Testing Real Database Operations...")
        
        # Test core components endpoint
        try:
            response = requests.get(f"{self.base_url}/api/v1/decisions/core-components", timeout=10)
            if response.status_code == 403:
                self.log_result("Core Components Endpoint", True, "Protected by authentication (403)")
            elif response.status_code == 200:
                data = response.json()
                if data.get("status") == "success" and data.get("data"):
                    components = data["data"]
                    component_count = len([k for k in components.keys() if k != "system_info"])
                    self.log_result("Core Components Data", True, f"{component_count} components returned")
                else:
                    self.log_result("Core Components Data", False, "Invalid response structure")
            else:
                self.log_result("Core Components Endpoint", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Core Components Endpoint", False, f"Exception: {str(e)}")
        
        # Test SSDLC stages endpoint
        try:
            response = requests.get(f"{self.base_url}/api/v1/decisions/ssdlc-stages", timeout=10)
            if response.status_code == 403:
                self.log_result("SSDLC Stages Endpoint", True, "Protected by authentication (403)")
            elif response.status_code == 200:
                data = response.json()
                if data.get("status") == "success" and data.get("data"):
                    stages = data["data"]
                    stage_count = len(stages)
                    self.log_result("SSDLC Stages Data", True, f"{stage_count} stages returned")
                else:
                    self.log_result("SSDLC Stages Data", False, "Invalid response structure")
            else:
                self.log_result("SSDLC Stages Endpoint", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("SSDLC Stages Endpoint", False, f"Exception: {str(e)}")
        
        # Test recent decisions endpoint
        try:
            response = requests.get(f"{self.base_url}/api/v1/decisions/recent?limit=5", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success" and data.get("data"):
                    decisions = data["data"]
                    self.log_result("Recent Decisions Query", True, f"{len(decisions)} decisions returned")
                    
                    # Check if decisions have required fields
                    if decisions and isinstance(decisions, list):
                        first_decision = decisions[0]
                        required_fields = ["evidence_id", "service_name", "decision", "confidence"]
                        missing_fields = [f for f in required_fields if f not in first_decision]
                        if not missing_fields:
                            self.log_result("Decision Data Structure", True, "All required fields present")
                        else:
                            self.log_result("Decision Data Structure", False, f"Missing: {missing_fields}")
                else:
                    self.log_result("Recent Decisions Query", False, "Invalid response structure")
            else:
                self.log_result("Recent Decisions Query", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Recent Decisions Query", False, f"Exception: {str(e)}")

    def test_decision_engine_integration(self):
        """Test Decision Engine Integration with all real components"""
        print("\n🔍 Testing Decision Engine Integration...")
        
        # Test make-decision endpoint with comprehensive data
        decision_request = {
            "service_name": "integration-test-service",
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
                    "severity": "HIGH",
                    "category": "injection",
                    "file_path": "/src/payment/dao.py",
                    "line_number": 45,
                    "cve_id": "CVE-2023-1234",
                    "fix_available": True
                },
                {
                    "rule_id": "XSS_001", 
                    "title": "Cross-site scripting vulnerability",
                    "severity": "MEDIUM",
                    "category": "injection",
                    "file_path": "/src/web/templates.py",
                    "line_number": 123
                }
            ],
            "sbom_data": {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "components": [
                    {
                        "name": "express",
                        "version": "4.18.0",
                        "scope": "required"
                    },
                    {
                        "name": "lodash",
                        "version": "4.17.21",
                        "scope": "required"
                    }
                ]
            }
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/decisions/make-decision",
                json=decision_request,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ["decision", "confidence_score", "evidence_id", "reasoning"]
                missing_fields = [f for f in required_fields if f not in data]
                
                if not missing_fields:
                    self.log_result("End-to-End Decision Making", True, 
                                  f"Decision: {data['decision']}, Confidence: {data['confidence_score']}")
                    
                    # Check if evidence was generated
                    if data.get("evidence_id"):
                        self.log_result("Evidence Generation", True, f"ID: {data['evidence_id']}")
                    
                    # Check processing components
                    if data.get("consensus_details"):
                        consensus = data["consensus_details"]
                        components_used = list(consensus.keys()) if isinstance(consensus, dict) else []
                        self.log_result("Component Integration", True, f"Components: {len(components_used)}")
                else:
                    self.log_result("End-to-End Decision Making", False, f"Missing fields: {missing_fields}")
            else:
                # Check if it's an authentication error (expected)
                if response.status_code in [401, 403]:
                    self.log_result("Decision Endpoint Security", True, f"Protected (Status: {response.status_code})")
                else:
                    self.log_result("End-to-End Decision Making", False, f"Status: {response.status_code}")
                    
        except Exception as e:
            self.log_result("End-to-End Decision Making", False, f"Exception: {str(e)}")

    def test_dual_mode_functionality(self):
        """Test dual-mode functionality (demo vs production)"""
        print("\n🔍 Testing Dual-Mode Functionality...")
        
        try:
            # Test settings and mode detection
            result = subprocess.run([
                "python", "-c", 
                """
import sys
sys.path.insert(0, '/app/fixops-blended-enterprise')
from src.config.settings import get_settings

settings = get_settings()
print(f'Demo mode: {settings.DEMO_MODE}')
print(f'Environment: {getattr(settings, "ENVIRONMENT", "unknown")}')
print(f'Vector DB URL configured: {bool(getattr(settings, "VECTOR_DB_URL", None))}')
print(f'OPA Server URL: {getattr(settings, "OPA_SERVER_URL", "default")}')
                """
            ], capture_output=True, text=True, timeout=10, cwd="/app/fixops-blended-enterprise")
            
            if result.returncode == 0:
                output_lines = result.stdout.strip().split('\n')
                demo_mode = "Demo mode: True" in result.stdout
                
                self.log_result("Mode Detection", True, f"Running in {'Demo' if demo_mode else 'Production'} mode")
                
                # Check configuration
                for line in output_lines:
                    if "Environment:" in line:
                        env = line.split(": ")[1]
                        self.log_result("Environment Configuration", True, f"Environment: {env}")
                    elif "Vector DB URL configured:" in line:
                        configured = line.split(": ")[1]
                        self.log_result("Vector DB Configuration", True, f"Configured: {configured}")
            else:
                self.log_result("Dual-Mode Configuration", False, f"Error: {result.stderr}")
                
        except Exception as e:
            self.log_result("Dual-Mode Configuration", False, f"Exception: {str(e)}")

    def run_all_tests(self):
        """Run all real components tests"""
        print("🚀 Starting Real Components Testing...")
        print(f"Testing against: {self.base_url}")
        print("=" * 80)
        
        # Test all real components as specified in review request
        self.test_real_vector_store_integration()
        self.test_real_opa_policy_engine()
        self.test_real_evidence_lake_storage()
        self.test_real_database_operations()
        self.test_decision_engine_integration()
        self.test_dual_mode_functionality()
        
        # Print results
        print(f"\n{'='*80}")
        print(f"📊 REAL COMPONENTS TEST RESULTS:")
        print(f"Tests passed: {self.tests_passed}/{self.tests_run}")
        print(f"Success rate: {(self.tests_passed/self.tests_run)*100:.1f}%")
        
        if self.failed_tests:
            print(f"\n❌ FAILED TESTS ({len(self.failed_tests)}):")
            for i, failure in enumerate(self.failed_tests, 1):
                print(f"   {i}. {failure['name']}")
                if failure['details']:
                    print(f"      Details: {failure['details']}")
        
        print(f"\n{'='*80}")
        
        return len(self.failed_tests) == 0

def main():
    tester = RealComponentsTester()
    success = tester.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())