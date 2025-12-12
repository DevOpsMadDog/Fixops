"""Code Repository Agent

Monitors code repositories and pushes SARIF, SBOM, and design context data.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agents.core.agent_framework import AgentConfig, AgentData, BaseAgent

logger = logging.getLogger(__name__)


class CodeRepoAgent(BaseAgent):
    """Agent that monitors code repositories."""

    def __init__(
        self,
        config: AgentConfig,
        fixops_api_url: str,
        fixops_api_key: str,
        repo_url: str,
        repo_branch: str = "main",
    ):
        """Initialize code repo agent."""
        super().__init__(config, fixops_api_url, fixops_api_key)
        self.repo_url = repo_url
        self.repo_branch = repo_branch
        self.last_commit: Optional[str] = None
        self.repo_path: Optional[str] = None

    async def connect(self) -> bool:
        """Connect to repository."""
        try:
            import git

            # Clone or update repository
            repo_name = self.repo_url.split("/")[-1].replace(".git", "")
            self.repo_path = f"/tmp/fixops-agents/{repo_name}"

            try:
                repo = git.Repo(self.repo_path)
                repo.remotes.origin.pull()
            except Exception:
                repo = git.Repo.clone_from(self.repo_url, self.repo_path)

            repo.git.checkout(self.repo_branch)
            self.last_commit = repo.head.commit.hexsha

            logger.info(f"Connected to repository: {self.repo_url}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to repository {self.repo_url}: {e}")
            return False

    async def disconnect(self):
        """Disconnect from repository."""
        # Keep repo cloned for future use

    async def collect_data(self) -> List[AgentData]:
        """Collect data from repository."""
        import git

        try:
            repo = git.Repo(self.repo_path)
            repo.remotes.origin.pull()
            repo.git.checkout(self.repo_branch)

            current_commit = repo.head.commit.hexsha

            # Check if there are new commits
            if current_commit == self.last_commit:
                return []  # No new data

            self.last_commit = current_commit

            data_items = []

            # Collect SARIF (run security scan)
            sarif_data = await self._collect_sarif()
            if sarif_data:
                data_items.append(
                    AgentData(
                        agent_id=self.config.agent_id,
                        timestamp=datetime.now(timezone.utc),
                        data_type="sarif",
                        data=sarif_data,
                        metadata={
                            "repo_url": self.repo_url,
                            "branch": self.repo_branch,
                            "commit": current_commit,
                        },
                    )
                )

            # Collect SBOM (generate from code)
            sbom_data = await self._collect_sbom()
            if sbom_data:
                data_items.append(
                    AgentData(
                        agent_id=self.config.agent_id,
                        timestamp=datetime.now(timezone.utc),
                        data_type="sbom",
                        data=sbom_data,
                        metadata={
                            "repo_url": self.repo_url,
                            "branch": self.repo_branch,
                            "commit": current_commit,
                        },
                    )
                )

            # Collect design context
            design_context = await self._collect_design_context()
            if design_context:
                data_items.append(
                    AgentData(
                        agent_id=self.config.agent_id,
                        timestamp=datetime.now(timezone.utc),
                        data_type="design_context",
                        data=design_context,
                        metadata={
                            "repo_url": self.repo_url,
                            "branch": self.repo_branch,
                            "commit": current_commit,
                        },
                    )
                )

            return data_items

        except Exception as e:
            logger.error(f"Error collecting data from {self.repo_url}: {e}")
            return []

    async def _collect_sarif(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF data by running security scan."""
        try:
            # Use proprietary analyzer or OSS fallback
            from risk.reachability.analyzer import VulnerabilityReachabilityAnalyzer

            VulnerabilityReachabilityAnalyzer(config={})

            # Run scan (simplified - would run actual scan)
            # In real implementation, would run proprietary or OSS scanner
            return {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "FixOps",
                                "version": "1.0.0",
                            }
                        },
                        "results": [],  # Would contain actual findings
                    }
                ],
            }

        except Exception as e:
            logger.error(f"Error collecting SARIF: {e}")
            return None

    async def _collect_sbom(self) -> Optional[Dict[str, Any]]:
        """Collect SBOM by generating from code."""
        try:
            from pathlib import Path

            from risk.sbom.generator import SBOMFormat, SBOMGenerator

            generator = SBOMGenerator()
            sbom = generator.generate_from_codebase(
                Path(self.repo_path), SBOMFormat.CYCLONEDX
            )

            return sbom

        except Exception as e:
            logger.error(f"Error collecting SBOM: {e}")
            return None

    async def _collect_design_context(self) -> Optional[Dict[str, Any]]:
        """Collect design context from repository."""
        try:
            # Extract design context (architecture, components, etc.)
            # In real implementation, would parse design docs, architecture diagrams, etc.
            return {
                "components": [],
                "architecture": {},
                "dependencies": {},
            }

        except Exception as e:
            logger.error(f"Error collecting design context: {e}")
            return None
