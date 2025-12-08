"""Agent Orchestrator

Orchestrates multiple agents and manages data flow from design-time to runtime.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from agents.core.agent_framework import AgentFramework, BaseAgent, AgentType

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """Orchestrates agents and manages data flow."""
    
    def __init__(self, framework: AgentFramework):
        """Initialize orchestrator."""
        self.framework = framework
        self.data_pipeline: Dict[str, List[Dict[str, Any]]] = {}
        self.correlation_rules: List[Dict[str, Any]] = []
    
    def add_correlation_rule(self, rule: Dict[str, Any]):
        """Add correlation rule for linking design-time to runtime data."""
        self.correlation_rules.append(rule)
        logger.info(f"Added correlation rule: {rule.get('name', 'unnamed')}")
    
    async def correlate_data(
        self, design_time_data: Dict[str, Any], runtime_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlate design-time and runtime data."""
        correlated = {
            "design_time": design_time_data,
            "runtime": runtime_data,
            "correlations": [],
        }
        
        for rule in self.correlation_rules:
            if self._matches_rule(design_time_data, runtime_data, rule):
                correlated["correlations"].append({
                    "rule": rule.get("name"),
                    "confidence": rule.get("confidence", 1.0),
                    "details": rule.get("details", {}),
                })
        
        return correlated
    
    def _matches_rule(
        self, design_data: Dict[str, Any], runtime_data: Dict[str, Any], rule: Dict[str, Any]
    ) -> bool:
        """Check if data matches correlation rule."""
        design_fields = rule.get("design_fields", [])
        runtime_fields = rule.get("runtime_fields", [])
        field_pairs = rule.get("field_pairs", [])
        
        if field_pairs:
            for pair in field_pairs:
                design_value = self._get_field_value(design_data, pair.get("design"))
                runtime_value = self._get_field_value(runtime_data, pair.get("runtime"))
                if design_value is None or runtime_value is None:
                    return False
                if design_value != runtime_value:
                    return False
            return True
        
        # Default behavior: compare same-named fields across data sets
        comparable_fields = set(design_fields).intersection(runtime_fields) or set(design_fields)
        for field in comparable_fields:
            design_value = self._get_field_value(design_data, field)
            runtime_value = self._get_field_value(runtime_data, field)
            if design_value is None or runtime_value is None:
                return False
            if design_value != runtime_value:
                return False
        
        # Ensure required runtime-only fields exist even if not compared
        for rf in runtime_fields:
            if self._get_field_value(runtime_data, rf) is None:
                return False
        
        return bool(comparable_fields or runtime_fields)

    def _get_field_value(self, payload: Dict[str, Any], field_path: Optional[str]) -> Any:
        """Safely fetch nested field values using dotted notation."""
        if not field_path:
            return None
        value: Any = payload
        for part in field_path.split("."):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        return value
    
    def get_agents_by_type(self, agent_type: AgentType) -> List[BaseAgent]:
        """Get all agents of a specific type."""
        return [
            agent
            for agent in self.framework.agents.values()
            if agent.config.agent_type == agent_type
        ]
    
    async def orchestrate_design_to_runtime(self):
        """Orchestrate data flow from design-time to runtime agents."""
        design_agents = self.get_agents_by_type(AgentType.DESIGN_TIME)
        runtime_agents = self.get_agents_by_type(AgentType.RUNTIME)
        
        logger.info(
            f"Orchestrating {len(design_agents)} design-time agents "
            f"and {len(runtime_agents)} runtime agents"
        )
        
        # Collect from design-time agents
        design_data = {}
        for agent in design_agents:
            if agent.status.value == "monitoring":
                try:
                    data = await agent.collect_data()
                    design_data[agent.config.agent_id] = data
                except Exception as e:
                    logger.error(f"Error collecting from {agent.config.agent_id}: {e}")
        
        # Collect from runtime agents
        runtime_data = {}
        for agent in runtime_agents:
            if agent.status.value == "monitoring":
                try:
                    data = await agent.collect_data()
                    runtime_data[agent.config.agent_id] = data
                except Exception as e:
                    logger.error(f"Error collecting from {agent.config.agent_id}: {e}")
        
        # Correlate and push
        for design_id, design_items in design_data.items():
            for runtime_id, runtime_items in runtime_data.items():
                for design_item in design_items:
                    for runtime_item in runtime_items:
                        correlated = await self.correlate_data(
                            design_item.data, runtime_item.data
                        )
                        
                        # Push correlated data
                        await self.framework.agents[design_id].push_data([
                            type(design_item)(
                                agent_id=f"{design_id}+{runtime_id}",
                                timestamp=design_item.timestamp,
                                data_type="correlated",
                                data=correlated,
                                metadata={
                                    "design_agent": design_id,
                                    "runtime_agent": runtime_id,
                                },
                            )
                        ])
