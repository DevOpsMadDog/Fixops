"""Agent Orchestrator

Orchestrates multiple agents and manages data flow from design-time to runtime.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from agents.core.agent_framework import AgentFramework, AgentType, BaseAgent

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
                correlated["correlations"].append(
                    {
                        "rule": rule.get("name"),
                        "confidence": rule.get("confidence", 1.0),
                        "details": rule.get("details", {}),
                    }
                )

        return correlated

    def _matches_rule(
        self,
        design_data: Dict[str, Any],
        runtime_data: Dict[str, Any],
        rule: Dict[str, Any],
    ) -> bool:
        """Check if data matches correlation rule."""
        # Check if all required fields exist
        design_fields = rule.get("design_fields", [])
        runtime_fields = rule.get("runtime_fields", [])

        for df in design_fields:
            if df not in design_data:
                return False

        for rf in runtime_fields:
            if rf not in runtime_data:
                return False

        # Compare field values for actual correlation
        correlations = rule.get("correlations", [])
        if not correlations:
            # If no specific correlations defined, just check field existence
            return True

        for correlation in correlations:
            design_field = correlation.get("design_field")
            runtime_field = correlation.get("runtime_field")
            match_type = correlation.get(
                "match_type", "exact"
            )  # exact, contains, regex

            if not design_field or not runtime_field:
                continue

            design_value = design_data.get(design_field)
            runtime_value = runtime_data.get(runtime_field)

            if match_type == "exact":
                if design_value != runtime_value:
                    return False
            elif match_type == "contains":
                if not (
                    design_value
                    and runtime_value
                    and str(design_value) in str(runtime_value)
                ):
                    return False
            elif match_type == "regex":
                import re

                pattern = correlation.get("pattern", "")
                if not (pattern and re.search(pattern, str(runtime_value))):
                    return False

        return True

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
                        await self.framework.agents[design_id].push_data(
                            [
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
                            ]
                        )
