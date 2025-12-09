"""Container Runtime Agent

Monitors container runtime and pushes container scan and runtime metrics.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agents.core.agent_framework import AgentConfig, AgentData, AgentType, BaseAgent

logger = logging.getLogger(__name__)


class ContainerAgent(BaseAgent):
    """Agent that monitors container runtime."""

    def __init__(
        self,
        config: AgentConfig,
        fixops_api_url: str,
        fixops_api_key: str,
        container_runtime: str = "docker",  # docker, containerd, cri-o
        k8s_cluster: Optional[str] = None,
    ):
        """Initialize container agent."""
        super().__init__(config, fixops_api_url, fixops_api_key)
        self.container_runtime = container_runtime
        self.k8s_cluster = k8s_cluster
        self.monitored_containers: Dict[str, Dict[str, Any]] = {}

    async def connect(self) -> bool:
        """Connect to container runtime."""
        try:
            if self.container_runtime == "docker":
                import docker

                self.client = docker.from_env()
                # Test connection
                self.client.ping()

            elif self.container_runtime == "kubernetes" and self.k8s_cluster:
                from kubernetes import client, config

                config.load_incluster_config()  # or load_kube_config()
                self.k8s_client = client.CoreV1Api()

            logger.info(f"Connected to {self.container_runtime} runtime")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to {self.container_runtime}: {e}")
            return False

    async def disconnect(self):
        """Disconnect from container runtime."""
        if hasattr(self, "client"):
            self.client.close()

    async def collect_data(self) -> List[AgentData]:
        """Collect data from container runtime."""
        try:
            data_items = []

            # Scan container images
            container_scans = await self._scan_containers()
            for scan in container_scans:
                data_items.append(
                    AgentData(
                        agent_id=self.config.agent_id,
                        timestamp=datetime.now(timezone.utc),
                        data_type="container_scan",
                        data=scan,
                        metadata={
                            "runtime": self.container_runtime,
                            "cluster": self.k8s_cluster,
                        },
                    )
                )

            # Collect runtime metrics
            runtime_metrics = await self._collect_runtime_metrics()
            if runtime_metrics:
                data_items.append(
                    AgentData(
                        agent_id=self.config.agent_id,
                        timestamp=datetime.now(timezone.utc),
                        data_type="runtime_metrics",
                        data=runtime_metrics,
                        metadata={
                            "runtime": self.container_runtime,
                            "cluster": self.k8s_cluster,
                        },
                    )
                )

            return data_items

        except Exception as e:
            logger.error(f"Error collecting container data: {e}")
            return []

    async def _scan_containers(self) -> List[Dict[str, Any]]:
        """Scan running containers."""
        scans = []

        try:
            if self.container_runtime == "docker":
                containers = self.client.containers.list()

                for container in containers:
                    image = (
                        container.image.tags[0] if container.image.tags else "unknown"
                    )

                    # Use proprietary scanner or OSS fallback
                    scan_result = await self._scan_container_image(image)

                    scans.append(
                        {
                            "container_id": container.id,
                            "image": image,
                            "scan_result": scan_result,
                            "status": container.status,
                        }
                    )

            elif self.container_runtime == "kubernetes":
                # Get pods
                pods = self.k8s_client.list_pod_for_all_namespaces()

                for pod in pods.items:
                    for container in pod.spec.containers:
                        image = container.image

                        scan_result = await self._scan_container_image(image)

                        scans.append(
                            {
                                "pod": pod.metadata.name,
                                "namespace": pod.metadata.namespace,
                                "container": container.name,
                                "image": image,
                                "scan_result": scan_result,
                            }
                        )

        except Exception as e:
            logger.error(f"Error scanning containers: {e}")

        return scans

    async def _scan_container_image(self, image: str) -> Dict[str, Any]:
        """Scan a container image."""
        try:
            # Use proprietary scanner or OSS fallback (Trivy, Clair, Grype)
            from risk.container.image_scanner import ContainerImageScanner

            scanner = ContainerImageScanner()
            result = scanner.scan_image(image)

            return result

        except Exception as e:
            logger.error(f"Error scanning image {image}: {e}")
            return {"error": str(e)}

    async def _collect_runtime_metrics(self) -> Optional[Dict[str, Any]]:
        """Collect runtime security metrics."""
        try:
            # Collect metrics from runtime security tools
            from risk.runtime.container import ContainerRuntimeSecurity

            security = ContainerRuntimeSecurity()
            metrics = security.collect_metrics()

            return metrics

        except Exception as e:
            logger.error(f"Error collecting runtime metrics: {e}")
            return None
