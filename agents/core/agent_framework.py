"""FixOps Agent Framework

Core framework for intelligent agents that connect to systems and push data.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AgentType(Enum):
    """Agent type categories."""

    DESIGN_TIME = "design_time"  # Code repos, CI/CD, design tools
    RUNTIME = "runtime"  # Containers, cloud, APIs
    LANGUAGE = "language"  # Language-specific agents
    IAC = "iac"  # Infrastructure as Code
    COMPLIANCE = "compliance"  # Compliance monitoring


class AgentStatus(Enum):
    """Agent status."""

    IDLE = "idle"
    CONNECTING = "connecting"
    MONITORING = "monitoring"
    COLLECTING = "collecting"
    PUSHING = "pushing"
    ERROR = "error"
    DISCONNECTED = "disconnected"


@dataclass
class AgentConfig:
    """Agent configuration."""

    agent_id: str
    agent_type: AgentType
    name: str
    enabled: bool = True
    connection_config: Dict[str, Any] = field(default_factory=dict)
    push_config: Dict[str, Any] = field(default_factory=dict)
    polling_interval: int = 60  # seconds
    retry_count: int = 3
    retry_delay: int = 5  # seconds
    timeout: int = 300  # seconds


@dataclass
class AgentData:
    """Data collected by agent."""

    agent_id: str
    timestamp: datetime
    data_type: str  # sarif, sbom, cve, design_context, runtime_metrics, etc.
    data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    """Base class for all FixOps agents."""

    def __init__(self, config: AgentConfig, fixops_api_url: str, fixops_api_key: str):
        """Initialize agent."""
        self.config = config
        self.fixops_api_url = fixops_api_url
        self.fixops_api_key = fixops_api_key
        self.status = AgentStatus.IDLE
        self.last_collection: Optional[datetime] = None
        self.last_push: Optional[datetime] = None
        self.error_count = 0
        self.collection_count = 0
        self.push_count = 0
        self._stop_requested = False

    @abstractmethod
    async def connect(self) -> bool:
        """Connect to target system."""

    @abstractmethod
    async def disconnect(self):
        """Disconnect from target system."""

    @abstractmethod
    async def collect_data(self) -> List[AgentData]:
        """Collect data from target system."""

    async def push_data(self, data: List[AgentData]) -> bool:
        """Push data to FixOps API."""
        import aiohttp

        try:
            self.status = AgentStatus.PUSHING

            async with aiohttp.ClientSession() as session:
                for agent_data in data:
                    # Push to appropriate FixOps endpoint
                    endpoint = self._get_endpoint(agent_data.data_type)
                    url = f"{self.fixops_api_url}{endpoint}"

                    headers = {
                        "X-API-Key": self.fixops_api_key,
                        "Content-Type": "application/json",
                    }

                    payload = {
                        "agent_id": agent_data.agent_id,
                        "timestamp": agent_data.timestamp.isoformat(),
                        "data_type": agent_data.data_type,
                        "data": agent_data.data,
                        "metadata": agent_data.metadata,
                    }

                    async with session.post(
                        url, json=payload, headers=headers
                    ) as response:
                        if response.status not in [200, 201]:
                            error_text = await response.text()
                            logger.error(
                                f"Failed to push {agent_data.data_type} from {self.config.agent_id}: "
                                f"{response.status} - {error_text}"
                            )
                            return False

                    self.push_count += 1
                    self.last_push = datetime.now(timezone.utc)

            logger.info(
                f"Successfully pushed {len(data)} data items from {self.config.agent_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Error pushing data from {self.config.agent_id}: {e}")
            self.error_count += 1
            return False

        finally:
            if not self._stop_requested:
                self.status = AgentStatus.MONITORING

    def request_stop(self):
        """Signal the agent to stop after the current iteration."""
        self._stop_requested = True

    def _get_endpoint(self, data_type: str) -> str:
        """Get FixOps API endpoint for data type."""
        endpoints = {
            "sarif": "/api/v1/ingest/sarif",
            "sbom": "/api/v1/ingest/sbom",
            "cve": "/api/v1/ingest/cve",
            "design_context": "/api/v1/ingest/design-context",
            "runtime_metrics": "/api/v1/ingest/runtime-metrics",
            "container_scan": "/api/v1/ingest/container-scan",
            "cloud_scan": "/api/v1/ingest/cloud-scan",
            "api_scan": "/api/v1/ingest/api-scan",
            "iac_scan": "/api/v1/ingest/iac-scan",
        }
        return endpoints.get(data_type, "/api/v1/ingest/data")

    async def run(self):
        """Main agent loop."""
        if not self.config.enabled:
            logger.info(f"Agent {self.config.agent_id} is disabled")
            return

        try:
            # Connect
            self.status = AgentStatus.CONNECTING
            if not await self.connect():
                self.status = AgentStatus.ERROR
                logger.error(f"Failed to connect agent {self.config.agent_id}")
                return

            self.status = AgentStatus.MONITORING

            # Main monitoring loop
            while not self._stop_requested and self.status != AgentStatus.DISCONNECTED:
                try:
                    # Collect data
                    self.status = AgentStatus.COLLECTING
                    data = await self.collect_data()
                    self.last_collection = datetime.now(timezone.utc)
                    self.collection_count += len(data)

                    if data:
                        # Push data
                        success = await self.push_data(data)
                        if not success:
                            self.error_count += 1

                    if self._stop_requested:
                        break

                    self.status = AgentStatus.MONITORING

                    # Wait for next polling interval
                    await asyncio.sleep(self.config.polling_interval)
                    if self._stop_requested:
                        break

                except Exception as e:
                    logger.error(f"Error in agent {self.config.agent_id} loop: {e}")
                    self.error_count += 1
                    self.status = AgentStatus.ERROR

                    # Retry logic
                    if self.error_count < self.config.retry_count:
                        await asyncio.sleep(self.config.retry_delay)
                        continue
                    else:
                        logger.error(
                            f"Agent {self.config.agent_id} exceeded retry count, stopping"
                        )
                        break

        except Exception as e:
            logger.error(f"Fatal error in agent {self.config.agent_id}: {e}")
            self.status = AgentStatus.ERROR

        finally:
            await self.disconnect()
            self.status = AgentStatus.DISCONNECTED

    def get_status(self) -> Dict[str, Any]:
        """Get agent status."""
        return {
            "agent_id": self.config.agent_id,
            "name": self.config.name,
            "type": self.config.agent_type.value,
            "status": self.status.value,
            "enabled": self.config.enabled,
            "last_collection": (
                self.last_collection.isoformat() if self.last_collection else None
            ),
            "last_push": (self.last_push.isoformat() if self.last_push else None),
            "collection_count": self.collection_count,
            "push_count": self.push_count,
            "error_count": self.error_count,
        }


class AgentFramework:
    """FixOps Agent Framework - Manages all agents."""

    def __init__(self, fixops_api_url: str, fixops_api_key: str):
        """Initialize agent framework."""
        self.fixops_api_url = fixops_api_url
        self.fixops_api_key = fixops_api_key
        self.agents: Dict[str, BaseAgent] = {}
        self.running = False

    def register_agent(self, agent: BaseAgent):
        """Register an agent."""
        self.agents[agent.config.agent_id] = agent
        logger.info(f"Registered agent: {agent.config.agent_id}")

    async def start_all(self):
        """Start all enabled agents."""
        self.running = True

        tasks = []
        for agent in self.agents.values():
            if agent.config.enabled:
                task = asyncio.create_task(agent.run())
                tasks.append(task)

        logger.info(f"Started {len(tasks)} agents")
        await asyncio.gather(*tasks, return_exceptions=True)

    async def stop_all(self):
        """Stop all agents."""
        self.running = False

        for agent in self.agents.values():
            agent.request_stop()

        logger.info("Stopped all agents")

    def get_all_status(self) -> List[Dict[str, Any]]:
        """Get status of all agents."""
        return [agent.get_status() for agent in self.agents.values()]
