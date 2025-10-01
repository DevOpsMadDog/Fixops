"""
Real OPA (Open Policy Agent) Engine for Production Mode
- Demo Mode: Uses local rego evaluation
- Production Mode: Connects to real OPA server and evaluates policies
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
import structlog

from src.config.settings import get_settings

logger = structlog.get_logger()
settings = get_settings()

class OPAEngine:
    """Base OPA Engine interface"""
    
    async def evaluate_policy(self, policy_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a policy with input data"""
        raise NotImplementedError
    
    async def health_check(self) -> bool:
        """Check if OPA engine is healthy"""
        raise NotImplementedError

class DemoOPAEngine(OPAEngine):
    """Demo OPA Engine with local rego evaluation"""
    
    def __init__(self):
        self.policies = {}
        self._load_demo_policies()
    
    def _load_demo_policies(self):
        """Load demo policies for local evaluation"""
        self.policies = {
            "vulnerability": {
                "rules": [
                    {
                        "name": "block_critical_vulns",
                        "description": "Block deployment with critical vulnerabilities",
                        "logic": "block if any vulnerability has severity=CRITICAL and fix_available=false"
                    },
                    {
                        "name": "allow_patched_vulns", 
                        "description": "Allow if all critical vulnerabilities have patches",
                        "logic": "allow if all CRITICAL vulnerabilities have fix_available=true"
                    }
                ]
            },
            "sbom": {
                "rules": [
                    {
                        "name": "require_sbom",
                        "description": "Require valid SBOM for deployment",
                        "logic": "block if sbom_present=false or sbom_valid=false"
                    },
                    {
                        "name": "validate_components",
                        "description": "Validate SBOM components have required fields",
                        "logic": "require name, version, supplier for all components"
                    }
                ]
            }
        }
        
        logger.info("🎭 Demo OPA policies loaded", policies=list(self.policies.keys()))
    
    async def evaluate_policy(self, policy_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate policy using demo logic"""
        try:
            start_time = time.perf_counter()
            
            if policy_name == "vulnerability":
                result = await self._evaluate_vulnerability_policy(input_data)
            elif policy_name == "sbom":
                result = await self._evaluate_sbom_policy(input_data)
            else:
                result = {
                    "decision": "allow",
                    "rationale": f"Unknown policy {policy_name} - default allow"
                }
            
            execution_time = (time.perf_counter() - start_time) * 1000
            result["execution_time_ms"] = execution_time
            result["demo_mode"] = True
            
            return result
            
        except Exception as e:
            logger.error(f"Demo OPA evaluation failed: {e}")
            return {
                "decision": "defer",
                "rationale": f"Policy evaluation error: {str(e)}",
                "error": True,
                "demo_mode": True
            }
    
    async def _evaluate_vulnerability_policy(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Demo vulnerability policy evaluation"""
        vulnerabilities = input_data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return {
                "decision": "allow",
                "rationale": "No vulnerabilities found"
            }
        
        # Check for critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "CRITICAL"]
        
        if not critical_vulns:
            return {
                "decision": "allow", 
                "rationale": f"No critical vulnerabilities among {len(vulnerabilities)} findings"
            }
        
        # Check if critical vulnerabilities have fixes
        unfixed_critical = [v for v in critical_vulns if not v.get("fix_available", False)]
        
        if unfixed_critical:
            return {
                "decision": "block",
                "rationale": f"Found {len(unfixed_critical)} critical vulnerabilities without fixes",
                "unfixed_critical_count": len(unfixed_critical),
                "critical_vulns": [v.get("cve_id", v.get("title", "Unknown")) for v in unfixed_critical]
            }
        else:
            return {
                "decision": "allow",
                "rationale": f"All {len(critical_vulns)} critical vulnerabilities have fixes available",
                "critical_with_fixes": len(critical_vulns)
            }
    
    async def _evaluate_sbom_policy(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Demo SBOM policy evaluation"""
        sbom_present = input_data.get("sbom_present", False)
        sbom_valid = input_data.get("sbom_valid", False)
        
        if not sbom_present:
            return {
                "decision": "block",
                "rationale": "SBOM is required but not present"
            }
        
        if not sbom_valid:
            return {
                "decision": "block", 
                "rationale": "SBOM is present but invalid"
            }
        
        # Check SBOM components if provided
        sbom_data = input_data.get("sbom", {})
        components = sbom_data.get("components", [])
        
        if not components:
            return {
                "decision": "allow",
                "rationale": "Valid SBOM present (no components to validate)"
            }
        
        # Validate required fields in components
        required_fields = ["name", "version"]
        invalid_components = []
        
        for component in components:
            missing_fields = [field for field in required_fields if not component.get(field)]
            if missing_fields:
                invalid_components.append({
                    "component": component.get("name", "unknown"),
                    "missing_fields": missing_fields
                })
        
        if invalid_components:
            return {
                "decision": "defer",
                "rationale": f"SBOM has {len(invalid_components)} components with missing required fields",
                "invalid_components": invalid_components[:5]  # Limit output
            }
        
        return {
            "decision": "allow",
            "rationale": f"Valid SBOM with {len(components)} properly formatted components"
        }
    
    async def health_check(self) -> bool:
        """Demo health check always returns True"""
        return True

class ProductionOPAEngine(OPAEngine):
    """Production OPA Engine with real OPA server"""
    
    def __init__(self, opa_url: str = "http://localhost:8181"):
        self.opa_url = opa_url.rstrip('/')
        self.client = None
        self._initialize_client()
        self.policy_cache = {}
    
    def _initialize_client(self):
        """Initialize OPA client"""
        try:
            from opa_python import OPAClient
            
            # Initialize OPA client
            self.client = OPAClient(host=self.opa_url)
            logger.info(f"✅ Production OPA client initialized: {self.opa_url}")
            
        except ImportError:
            logger.error("opa-python not available, falling back to HTTP requests")
            self.client = None
        except Exception as e:
            logger.error(f"OPA client initialization failed: {e}")
            self.client = None
    
    async def evaluate_policy(self, policy_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate policy using real OPA server"""
        try:
            start_time = time.perf_counter()
            
            if self.client:
                result = await self._evaluate_with_client(policy_name, input_data)
            else:
                result = await self._evaluate_with_http(policy_name, input_data)
            
            execution_time = (time.perf_counter() - start_time) * 1000
            result["execution_time_ms"] = execution_time
            result["demo_mode"] = False
            
            return result
            
        except Exception as e:
            logger.error(f"Production OPA evaluation failed: {e}")
            return {
                "decision": "defer",
                "rationale": f"OPA server error: {str(e)}",
                "error": True,
                "demo_mode": False
            }
    
    async def _evaluate_with_client(self, policy_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate using OPA Python client"""
        try:
            # Query OPA for policy decision
            policy_path = f"fixops/{policy_name}/allow"
            result = await asyncio.to_thread(
                self.client.query, 
                policy_path, 
                input_data=input_data
            )
            
            # Convert OPA result to our format
            if result.get("result"):
                return {
                    "decision": "allow",
                    "rationale": f"OPA policy {policy_name} evaluation passed"
                }
            else:
                return {
                    "decision": "block",
                    "rationale": f"OPA policy {policy_name} evaluation failed"
                }
                
        except Exception as e:
            logger.error(f"OPA client evaluation failed: {e}")
            raise
    
    async def _evaluate_with_http(self, policy_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate using HTTP requests to OPA server"""
        import aiohttp
        
        try:
            policy_path = f"fixops/{policy_name}/allow"
            url = f"{self.opa_url}/v1/data/{policy_path}"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json={"input": input_data},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        if result.get("result"):
                            return {
                                "decision": "allow",
                                "rationale": f"OPA policy {policy_name} evaluation passed",
                                "opa_result": result
                            }
                        else:
                            return {
                                "decision": "block", 
                                "rationale": f"OPA policy {policy_name} evaluation failed",
                                "opa_result": result
                            }
                    else:
                        raise Exception(f"OPA server responded with status {response.status}")
                        
        except Exception as e:
            logger.error(f"OPA HTTP evaluation failed: {e}")
            raise
    
    async def health_check(self) -> bool:
        """Check if OPA server is healthy"""
        try:
            import aiohttp
            
            url = f"{self.opa_url}/health"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=3)
                ) as response:
                    return response.status == 200
                    
        except Exception as e:
            logger.error(f"OPA health check failed: {e}")
            return False

class OPAEngineFactory:
    """Factory for creating OPA engines based on mode"""
    
    @staticmethod
    def create(settings=None) -> OPAEngine:
        """Create OPA engine based on demo mode setting"""
        if settings is None:
            settings = get_settings()
        
        if settings.DEMO_MODE:
            logger.info("🎭 Creating Demo OPA Engine (local evaluation)")
            return DemoOPAEngine()
        else:
            opa_url = getattr(settings, 'OPA_SERVER_URL', 'http://localhost:8181')
            logger.info(f"🏭 Creating Production OPA Engine: {opa_url}")
            return ProductionOPAEngine(opa_url)

# Global OPA engine instance
_opa_engine_instance: Optional[OPAEngine] = None

async def get_opa_engine() -> OPAEngine:
    """Get singleton OPA engine instance"""
    global _opa_engine_instance
    
    if _opa_engine_instance is None:
        _opa_engine_instance = OPAEngineFactory.create()
    
    return _opa_engine_instance

# Convenience functions
async def evaluate_vulnerability_policy(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate vulnerability policy"""
    engine = await get_opa_engine()
    return await engine.evaluate_policy("vulnerability", {"vulnerabilities": vulnerabilities})

async def evaluate_sbom_policy(sbom_present: bool, sbom_valid: bool, sbom_data: Optional[Dict] = None) -> Dict[str, Any]:
    """Evaluate SBOM policy"""
    engine = await get_opa_engine()
    input_data = {
        "sbom_present": sbom_present,
        "sbom_valid": sbom_valid
    }
    if sbom_data:
        input_data["sbom"] = sbom_data
    
    return await engine.evaluate_policy("sbom", input_data)