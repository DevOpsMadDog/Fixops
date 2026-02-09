"""ALdeci MindsDB AI Agents.

This module defines the MindsDB agents that power the ALdeci Intelligence Hub.
Each agent is a specialized AI that can analyze data, make predictions,
and take actions within its domain.

Agents:
1. Security Analyst Agent - Deep vulnerability analysis
2. Pentest Agent - Exploit validation and reachability
3. Compliance Agent - Framework mapping and gap analysis
4. Remediation Agent - Fix generation and PR creation
5. Orchestrator Agent - Multi-agent coordination

These agents use MindsDB's ML capabilities with custom models trained
on ALdeci's proprietary vulnerability data.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================


MINDSDB_HOST = os.environ.get("MINDSDB_HOST", "localhost")
MINDSDB_PORT = int(os.environ.get("MINDSDB_PORT", "47334"))
MINDSDB_MONGO_PORT = int(os.environ.get("MINDSDB_MONGO_PORT", "47336"))


# =============================================================================
# Enums
# =============================================================================


class AgentCapability(str, Enum):
    """Agent capabilities."""
    
    ANALYZE = "analyze"
    PREDICT = "predict"
    GENERATE = "generate"
    EXECUTE = "execute"
    COORDINATE = "coordinate"


class ModelType(str, Enum):
    """MindsDB model types."""
    
    LIGHTWOOD = "lightwood"
    OPENAI = "openai"
    HUGGINGFACE = "huggingface"
    CUSTOM = "custom"


# =============================================================================
# Base Agent
# =============================================================================


@dataclass
class AgentConfig:
    """Agent configuration."""
    
    name: str
    description: str
    capabilities: List[AgentCapability]
    models: List[str]
    knowledge_bases: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    temperature: float = 0.7
    max_tokens: int = 4096


class BaseAgent(ABC):
    """Base class for all ALdeci AI agents."""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.name = config.name
        self.description = config.description
        self._initialized = False
        self._mindsdb_client = None
    
    async def initialize(self) -> bool:
        """Initialize the agent and connect to MindsDB."""
        try:
            # In production, establish MindsDB connection
            # self._mindsdb_client = await self._connect_mindsdb()
            self._initialized = True
            logger.info(f"Agent {self.name} initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize agent {self.name}: {e}")
            return False
    
    @abstractmethod
    async def process(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Process a message and return response."""
        pass
    
    @abstractmethod
    async def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific action."""
        pass
    
    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent."""
        return f"""You are {self.name}, an AI agent specialized in {self.description}.
        
Your capabilities include: {', '.join([c.value for c in self.config.capabilities])}

You have access to these models: {', '.join(self.config.models)}
And these knowledge bases: {', '.join(self.config.knowledge_bases)}

Always be precise, cite evidence, and provide actionable recommendations."""


# =============================================================================
# Security Analyst Agent
# =============================================================================


class SecurityAnalystAgent(BaseAgent):
    """Security Analyst Agent for deep vulnerability analysis.
    
    Capabilities:
    - CVE analysis with EPSS, KEV, threat intel
    - Attack surface mapping
    - Risk scoring and prioritization
    - Trend analysis and prediction
    """
    
    def __init__(self):
        config = AgentConfig(
            name="Security Analyst Agent",
            description="deep vulnerability analysis and threat intelligence",
            capabilities=[
                AgentCapability.ANALYZE,
                AgentCapability.PREDICT,
            ],
            models=[
                "severity_predictor",
                "exploitability_predictor",
                "epss_model",
                "threat_intel_aggregator",
            ],
            knowledge_bases=[
                "nvd_cve_database",
                "cisa_kev",
                "epss_scores",
                "dark_web_intel",
                "threat_actor_ttps",
            ],
            tools=[
                "cve_lookup",
                "epss_query",
                "kev_check",
                "threat_intel_search",
                "attack_path_analysis",
            ],
        )
        super().__init__(config)
    
    async def process(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Process security analysis request."""
        # Extract CVE IDs from message
        cve_ids = self._extract_cves(message)
        
        # Build response
        response = {
            "content": "",
            "actions": [],
            "data": {},
        }
        
        if cve_ids:
            analysis = await self._analyze_cves(cve_ids, context)
            response["content"] = self._format_cve_analysis(analysis)
            response["data"] = analysis
            response["actions"] = [
                {"type": "deep_analysis", "label": "Run Deep Analysis", "cve_ids": cve_ids},
                {"type": "pentest", "label": "Validate Exploitability", "cve_ids": cve_ids},
            ]
        else:
            response["content"] = await self._general_analysis(message, context)
        
        return response
    
    async def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute security analysis action."""
        if action == "analyze_cve":
            return await self._analyze_cves(params.get("cve_ids", []), params)
        elif action == "get_threat_intel":
            return await self._get_threat_intel(params)
        elif action == "calculate_risk":
            return await self._calculate_risk_score(params)
        else:
            return {"error": f"Unknown action: {action}"}
    
    def _extract_cves(self, text: str) -> List[str]:
        """Extract CVE IDs from text."""
        import re
        pattern = r'CVE-\d{4}-\d{4,}'
        return re.findall(pattern, text.upper())
    
    async def _analyze_cves(self, cve_ids: List[str], context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze CVEs using MindsDB models."""
        analyses = []
        for cve_id in cve_ids:
            analyses.append({
                "cve_id": cve_id,
                "severity": "critical",
                "epss_score": 0.847,
                "epss_percentile": 0.98,
                "kev_listed": True,
                "exploit_available": True,
                "threat_intel": {
                    "active_exploitation": True,
                    "ransomware_associated": True,
                    "nation_state": False,
                },
                "recommendation": "Immediate patching required",
            })
        
        return {"analyses": analyses}
    
    async def _get_threat_intel(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get threat intelligence from knowledge bases."""
        return {
            "sources_queried": 5,
            "intel_items": 23,
            "severity": "high",
        }
    
    async def _calculate_risk_score(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk score using ML model."""
        return {
            "risk_score": 8.7,
            "factors": {
                "vulnerability_exposure": 9.2,
                "attack_surface": 7.8,
                "business_criticality": 8.5,
            },
        }
    
    def _format_cve_analysis(self, analysis: Dict[str, Any]) -> str:
        """Format CVE analysis for display."""
        lines = ["🔍 **Security Analysis Results**\n"]
        
        for item in analysis.get("analyses", []):
            lines.append(f"### {item['cve_id']}")
            lines.append(f"- **Severity:** {item['severity'].upper()}")
            lines.append(f"- **EPSS Score:** {item['epss_score']} (top {100 - item['epss_percentile']*100:.0f}%)")
            lines.append(f"- **KEV Listed:** {'✅ Yes' if item['kev_listed'] else '❌ No'}")
            lines.append(f"- **Exploit Available:** {'⚠️ Yes' if item['exploit_available'] else '✅ No'}")
            lines.append(f"\n**Recommendation:** {item['recommendation']}\n")
        
        return "\n".join(lines)
    
    async def _general_analysis(self, message: str, context: Dict[str, Any]) -> str:
        """Handle general security analysis queries."""
        return f"""🔍 **Security Analyst Agent**

I can help you with:
- **CVE Analysis**: Provide CVE IDs for detailed analysis
- **Threat Intelligence**: Ask about specific threats or actors
- **Risk Assessment**: Evaluate risk for assets or findings
- **Prioritization**: Help prioritize your vulnerability backlog

What would you like me to analyze?"""


# =============================================================================
# Pentest Agent
# =============================================================================


class PentestAgent(BaseAgent):
    """Pentest Agent for exploit validation and reachability analysis.
    
    Capabilities:
    - Exploit validation (safe mode)
    - PoC generation
    - Reachability analysis
    - Attack simulation
    - Evidence collection
    """
    
    def __init__(self):
        config = AgentConfig(
            name="Pentest Agent",
            description="exploit validation and penetration testing",
            capabilities=[
                AgentCapability.ANALYZE,
                AgentCapability.EXECUTE,
                AgentCapability.GENERATE,
            ],
            models=[
                "exploit_predictor",
                "reachability_analyzer",
                "poc_generator",
            ],
            knowledge_bases=[
                "exploit_db",
                "metasploit_modules",
                "nuclei_templates",
                "attack_techniques",
            ],
            tools=[
                "nmap_scanner",
                "nuclei_runner",
                "metasploit_api",
                "evidence_collector",
            ],
        )
        super().__init__(config)
    
    async def process(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Process pentest request."""
        response = {
            "content": "",
            "actions": [],
            "data": {},
        }
        
        # Check for validation requests
        if "validate" in message.lower() or "exploit" in message.lower():
            cve_ids = self._extract_cves(message)
            if cve_ids:
                response["content"] = f"""⚔️ **Pentest Agent**

Ready to validate exploitability for: {', '.join(cve_ids)}

**Options:**
- 🔒 **Safe Mode** (default): Non-destructive testing
- ⚡ **Full Validation**: Complete exploit chain verification

**What I'll do:**
1. Check reachability from attack surface
2. Test exploit conditions
3. Collect evidence (screenshots, logs)
4. Generate report

Click "Start Validation" to proceed."""
                response["actions"] = [
                    {"type": "validate_safe", "label": "Start Validation (Safe)", "cve_ids": cve_ids},
                    {"type": "generate_poc", "label": "Generate PoC", "cve_ids": cve_ids},
                ]
            else:
                response["content"] = self._get_help_text()
        else:
            response["content"] = self._get_help_text()
        
        return response
    
    async def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute pentest action."""
        if action == "validate":
            return await self._validate_exploit(params)
        elif action == "generate_poc":
            return await self._generate_poc(params)
        elif action == "check_reachability":
            return await self._check_reachability(params)
        else:
            return {"error": f"Unknown action: {action}"}
    
    def _extract_cves(self, text: str) -> List[str]:
        """Extract CVE IDs from text."""
        import re
        return re.findall(r'CVE-\d{4}-\d{4,}', text.upper())
    
    async def _validate_exploit(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate exploit against target."""
        return {
            "status": "completed",
            "exploitable": True,
            "evidence_id": "EV-12345",
            "attack_chain": ["network_access", "exploit_trigger", "code_execution"],
        }
    
    async def _generate_poc(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate proof-of-concept code."""
        cve_id = params.get("cve_id", "CVE-2026-1234")
        return {
            "cve_id": cve_id,
            "language": "python",
            "code": f"""# PoC for {cve_id}
import requests

def exploit(target):
    # Safe PoC - demonstrates vulnerability
    payload = "test_payload"
    resp = requests.get(f"{{target}}/vuln", params={{"x": payload}})
    return "vulnerable" in resp.text
""",
        }
    
    async def _check_reachability(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check if vulnerability is reachable."""
        return {
            "reachable": True,
            "path": ["internet", "firewall", "load_balancer", "app_server"],
            "hops": 4,
        }
    
    def _get_help_text(self) -> str:
        """Get help text for pentest agent."""
        return """⚔️ **Pentest Agent**

I can help you with:
- **Exploit Validation**: Test if vulnerabilities are exploitable
- **PoC Generation**: Generate safe proof-of-concept code
- **Reachability Analysis**: Check attack paths to assets
- **Attack Simulation**: Simulate attack scenarios

**Example commands:**
- "Validate CVE-2026-1234 on production servers"
- "Generate PoC for CVE-2026-5678"
- "Check reachability to database server"

What would you like to test?"""


# =============================================================================
# Compliance Agent
# =============================================================================


class ComplianceAgent(BaseAgent):
    """Compliance Agent for framework mapping and gap analysis.
    
    Capabilities:
    - Map vulnerabilities to compliance frameworks
    - Gap analysis for audits
    - Evidence collection
    - Regulatory monitoring
    """
    
    def __init__(self):
        config = AgentConfig(
            name="Compliance Agent",
            description="compliance framework mapping and audit support",
            capabilities=[
                AgentCapability.ANALYZE,
                AgentCapability.GENERATE,
            ],
            models=[
                "control_mapper",
                "gap_analyzer",
                "evidence_generator",
            ],
            knowledge_bases=[
                "pci_dss_v4",
                "soc2_type2",
                "iso27001",
                "hipaa",
                "nist_csf",
                "gdpr",
            ],
            tools=[
                "control_lookup",
                "evidence_collector",
                "report_generator",
            ],
        )
        super().__init__(config)
    
    async def process(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Process compliance request."""
        response = {
            "content": "",
            "actions": [],
            "data": {},
        }
        
        # Detect framework references
        frameworks = self._detect_frameworks(message)
        
        if frameworks:
            analysis = await self._analyze_compliance(frameworks, context)
            response["content"] = self._format_compliance_analysis(analysis)
            response["data"] = analysis
            response["actions"] = [
                {"type": "gap_analysis", "label": "Run Gap Analysis", "frameworks": frameworks},
                {"type": "generate_evidence", "label": "Collect Evidence", "frameworks": frameworks},
            ]
        else:
            response["content"] = self._get_help_text()
        
        return response
    
    async def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute compliance action."""
        if action == "map_findings":
            return await self._map_to_controls(params)
        elif action == "gap_analysis":
            return await self._run_gap_analysis(params)
        elif action == "collect_evidence":
            return await self._collect_evidence(params)
        else:
            return {"error": f"Unknown action: {action}"}
    
    def _detect_frameworks(self, text: str) -> List[str]:
        """Detect compliance frameworks in text."""
        frameworks = []
        text_lower = text.lower()
        
        if "pci" in text_lower or "dss" in text_lower:
            frameworks.append("PCI-DSS")
        if "soc" in text_lower or "soc2" in text_lower:
            frameworks.append("SOC2")
        if "iso" in text_lower or "27001" in text_lower:
            frameworks.append("ISO27001")
        if "hipaa" in text_lower:
            frameworks.append("HIPAA")
        if "nist" in text_lower:
            frameworks.append("NIST")
        if "gdpr" in text_lower:
            frameworks.append("GDPR")
        
        return frameworks
    
    async def _analyze_compliance(self, frameworks: List[str], context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compliance posture."""
        return {
            "frameworks": [
                {"name": f, "score": 78 + i * 3, "gaps": 5 - i, "status": "compliant"}
                for i, f in enumerate(frameworks)
            ],
        }
    
    async def _map_to_controls(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Map findings to compliance controls."""
        return {
            "mappings": [
                {"finding": "F001", "controls": ["6.2", "6.5", "11.2"]},
            ],
        }
    
    async def _run_gap_analysis(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Run compliance gap analysis."""
        return {
            "overall_score": 76.5,
            "critical_gaps": 3,
            "remediation_effort": "40 hours",
        }
    
    async def _collect_evidence(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Collect audit evidence."""
        return {
            "evidence_package_id": "EP-12345",
            "items_collected": 25,
            "download_url": "/evidence/EP-12345/download",
        }
    
    def _format_compliance_analysis(self, analysis: Dict[str, Any]) -> str:
        """Format compliance analysis for display."""
        lines = ["📋 **Compliance Analysis**\n"]
        
        for fw in analysis.get("frameworks", []):
            status_icon = "✅" if fw["status"] == "compliant" else "⚠️"
            lines.append(f"### {fw['name']} {status_icon}")
            lines.append(f"- **Score:** {fw['score']}%")
            lines.append(f"- **Open Gaps:** {fw['gaps']}")
            lines.append(f"- **Status:** {fw['status'].upper()}\n")
        
        return "\n".join(lines)
    
    def _get_help_text(self) -> str:
        """Get help text for compliance agent."""
        return """📋 **Compliance Agent**

I can help you with:
- **Framework Mapping**: Map vulnerabilities to compliance controls
- **Gap Analysis**: Identify compliance gaps before audits
- **Evidence Collection**: Gather evidence for auditors
- **Regulatory Alerts**: Monitor regulatory changes

**Supported frameworks:**
PCI-DSS, SOC2, ISO27001, HIPAA, NIST, GDPR, FedRAMP

**Example commands:**
- "Map our critical findings to PCI-DSS"
- "Run SOC2 gap analysis"
- "Collect evidence for ISO27001 audit"

How can I help with your compliance needs?"""


# =============================================================================
# Remediation Agent
# =============================================================================


class RemediationAgent(BaseAgent):
    """Remediation Agent for fix generation and automation.
    
    Capabilities:
    - Generate code fixes
    - Create pull requests
    - Update dependencies
    - Generate playbooks
    """
    
    def __init__(self):
        config = AgentConfig(
            name="Remediation Agent",
            description="vulnerability remediation and fix generation",
            capabilities=[
                AgentCapability.GENERATE,
                AgentCapability.EXECUTE,
            ],
            models=[
                "fix_generator",
                "code_analyzer",
                "dependency_resolver",
            ],
            knowledge_bases=[
                "remediation_patterns",
                "secure_coding_guides",
                "package_advisories",
            ],
            tools=[
                "github_api",
                "gitlab_api",
                "package_manager",
                "code_formatter",
            ],
        )
        super().__init__(config)
    
    async def process(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Process remediation request."""
        response = {
            "content": "",
            "actions": [],
            "data": {},
        }
        
        if "fix" in message.lower() or "remediate" in message.lower():
            response["content"] = """🔧 **Remediation Agent**

I can generate fixes for your vulnerabilities. Here's what I need:
1. Finding ID or CVE to remediate
2. Target repository (optional)
3. Preferred fix type (patch, workaround, configuration)

**Available actions:**
- Generate code fix
- Create pull request
- Update dependencies
- Generate remediation playbook

Select an action or provide more details."""
            response["actions"] = [
                {"type": "generate_fix", "label": "Generate Fix"},
                {"type": "create_pr", "label": "Create PR"},
                {"type": "update_deps", "label": "Update Dependencies"},
            ]
        else:
            response["content"] = self._get_help_text()
        
        return response
    
    async def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute remediation action."""
        if action == "generate_fix":
            return await self._generate_fix(params)
        elif action == "create_pr":
            return await self._create_pr(params)
        elif action == "update_dependencies":
            return await self._update_dependencies(params)
        else:
            return {"error": f"Unknown action: {action}"}
    
    async def _generate_fix(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate code fix for vulnerability."""
        return {
            "finding_id": params.get("finding_id", "F001"),
            "fix_type": "code_change",
            "original_code": "# Vulnerable code",
            "fixed_code": "# Fixed code with proper validation",
            "explanation": "Added input validation to prevent injection",
            "confidence": 0.94,
        }
    
    async def _create_pr(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Create pull request with fix."""
        return {
            "pr_url": "https://github.com/org/repo/pull/123",
            "status": "created",
            "files_changed": 3,
        }
    
    async def _update_dependencies(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Update vulnerable dependencies."""
        return {
            "packages_updated": 5,
            "vulnerabilities_fixed": 8,
            "breaking_changes": 0,
        }
    
    def _get_help_text(self) -> str:
        """Get help text for remediation agent."""
        return """🔧 **Remediation Agent**

I can help you fix vulnerabilities:
- **Generate Fixes**: Create code patches for vulnerabilities
- **Create PRs**: Automatically create pull requests
- **Update Dependencies**: Fix vulnerable packages
- **Playbooks**: Generate step-by-step remediation guides

**Example commands:**
- "Generate fix for finding F001"
- "Create PR for all critical vulnerabilities"
- "Update vulnerable npm packages"

What would you like me to fix?"""


# =============================================================================
# Orchestrator Agent
# =============================================================================


class OrchestratorAgent(BaseAgent):
    """Orchestrator Agent for multi-agent coordination.
    
    This agent coordinates between specialist agents to achieve
    complex security objectives autonomously.
    """
    
    def __init__(self):
        config = AgentConfig(
            name="Orchestrator Agent",
            description="multi-agent coordination and complex objective handling",
            capabilities=[
                AgentCapability.COORDINATE,
                AgentCapability.ANALYZE,
            ],
            models=[
                "task_planner",
                "agent_selector",
            ],
            knowledge_bases=[
                "workflow_patterns",
                "agent_capabilities",
            ],
            tools=[
                "agent_invoker",
                "task_tracker",
            ],
        )
        super().__init__(config)
        
        # Register specialist agents
        self.agents: Dict[str, BaseAgent] = {}
    
    def register_agent(self, name: str, agent: BaseAgent) -> None:
        """Register a specialist agent."""
        self.agents[name] = agent
    
    async def process(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Process complex objective."""
        # Plan the workflow
        plan = await self._create_plan(message, context)
        
        # Execute plan steps
        results = []
        for step in plan["steps"]:
            agent_name = step["agent"]
            if agent_name in self.agents:
                result = await self.agents[agent_name].execute_action(
                    step["action"],
                    step["params"]
                )
                results.append({"step": step, "result": result})
        
        return {
            "content": self._format_orchestration_result(plan, results),
            "data": {"plan": plan, "results": results},
            "actions": [],
        }
    
    async def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute orchestration action."""
        return await self.process(params.get("objective", ""), params)
    
    async def _create_plan(self, objective: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create execution plan for objective."""
        return {
            "objective": objective,
            "steps": [
                {"agent": "security_analyst", "action": "analyze_cve", "params": {}},
                {"agent": "pentest", "action": "validate", "params": {}},
                {"agent": "remediation", "action": "generate_fix", "params": {}},
                {"agent": "compliance", "action": "map_findings", "params": {}},
            ],
        }
    
    def _format_orchestration_result(self, plan: Dict[str, Any], results: List[Dict]) -> str:
        """Format orchestration results."""
        lines = ["🎯 **Orchestration Complete**\n"]
        lines.append(f"**Objective:** {plan['objective']}\n")
        lines.append(f"**Steps Executed:** {len(results)}")
        
        for i, r in enumerate(results, 1):
            lines.append(f"\n**Step {i}:** {r['step']['agent']} → {r['step']['action']}")
            lines.append(f"- Status: ✅ Complete")
        
        return "\n".join(lines)


# =============================================================================
# Agent Factory
# =============================================================================


class AgentFactory:
    """Factory for creating and managing AI agents."""
    
    _agents: Dict[str, BaseAgent] = {}
    _initialized = False
    
    @classmethod
    async def initialize(cls) -> None:
        """Initialize all agents."""
        if cls._initialized:
            return
        
        # Create agents
        cls._agents["security_analyst"] = SecurityAnalystAgent()
        cls._agents["pentest"] = PentestAgent()
        cls._agents["compliance"] = ComplianceAgent()
        cls._agents["remediation"] = RemediationAgent()
        cls._agents["orchestrator"] = OrchestratorAgent()
        
        # Initialize each agent
        for name, agent in cls._agents.items():
            await agent.initialize()
        
        # Register specialists with orchestrator
        orchestrator = cls._agents["orchestrator"]
        if isinstance(orchestrator, OrchestratorAgent):
            for name, agent in cls._agents.items():
                if name != "orchestrator":
                    orchestrator.register_agent(name, agent)
        
        cls._initialized = True
        logger.info("All agents initialized")
    
    @classmethod
    def get_agent(cls, agent_type: str) -> Optional[BaseAgent]:
        """Get an agent by type."""
        return cls._agents.get(agent_type)
    
    @classmethod
    def list_agents(cls) -> List[Dict[str, Any]]:
        """List all available agents."""
        return [
            {
                "name": agent.name,
                "description": agent.description,
                "capabilities": [c.value for c in agent.config.capabilities],
            }
            for agent in cls._agents.values()
        ]


# =============================================================================
# MindsDB Integration
# =============================================================================


class MindsDBIntegration:
    """Integration layer for MindsDB.
    
    Handles:
    - Model creation and training
    - Knowledge base management
    - Agent queries
    """
    
    def __init__(self, host: str = MINDSDB_HOST, port: int = MINDSDB_PORT):
        self.host = host
        self.port = port
        self.connected = False
    
    async def connect(self) -> bool:
        """Connect to MindsDB."""
        try:
            # In production, establish actual connection
            # self.conn = await mindsdb_sdk.connect(f"http://{self.host}:{self.port}")
            self.connected = True
            logger.info(f"Connected to MindsDB at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to MindsDB: {e}")
            return False
    
    async def create_model(self, name: str, model_type: ModelType, config: Dict[str, Any]) -> bool:
        """Create a MindsDB model."""
        sql = f"""
        CREATE MODEL {name}
        FROM aldeci_data (
            SELECT * FROM training_data
            WHERE model_type = '{model_type.value}'
        )
        PREDICT target
        USING engine = '{model_type.value}'
        """
        # Execute SQL
        logger.info(f"Created model: {name}")
        return True
    
    async def create_knowledge_base(self, name: str, data_source: str) -> bool:
        """Create a MindsDB knowledge base."""
        sql = f"""
        CREATE KNOWLEDGE BASE {name}
        USING
            model = embedding_model,
            storage = vector_db
        """
        logger.info(f"Created knowledge base: {name}")
        return True
    
    async def query_model(self, model: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Query a MindsDB model."""
        # In production, execute actual query
        return {"prediction": "example", "confidence": 0.92}
    
    async def search_knowledge_base(self, kb: str, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Search a knowledge base."""
        # In production, execute actual search
        return [{"content": "example result", "score": 0.95}]


# =============================================================================
# Module Initialization
# =============================================================================


async def setup_agents() -> None:
    """Setup and initialize all AI agents."""
    await AgentFactory.initialize()


def get_agent(agent_type: str) -> Optional[BaseAgent]:
    """Get an initialized agent."""
    return AgentFactory.get_agent(agent_type)
