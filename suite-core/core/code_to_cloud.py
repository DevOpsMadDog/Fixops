"""Code-to-Cloud Traceability Engine — Apiiro Killer.

Full provenance chain: code change → build artifact → deployment → runtime finding.
Tracks who wrote what, when it was deployed, and which findings it caused.

Features:
  - Code Change Tracking  (git commits, files, functions, deps)
  - Build Artifact Mapping  (commit → Docker image / wheel / npm package)
  - Deployment Tracking  (artifact → K8s / cloud / EC2)
  - Runtime Correlation  (finding → code change → developer)
  - Material Change Detection  (auth, crypto, infra, data — auto-trigger review)
  - Blast Radius Analysis  (services, APIs, data flows, compliance controls)
  - Developer Risk Profile  (security-relevant changes, defect rate — NOT blame)
  - Timeline Reconstruction  (code written → built → deployed → vuln discovered)

Usage:
    from core.code_to_cloud import CodeToCloudEngine, get_engine

    engine = get_engine()
    result = engine.trace_finding("FINDING-123")
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ChangeRisk(str, Enum):
    """Risk classification for a code change."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ChangeCategory(str, Enum):
    """Semantic category of a code change."""
    SECURITY = "security"        # auth, crypto, input validation, secrets
    INFRASTRUCTURE = "infrastructure"  # Terraform, K8s, CI/CD
    DATA = "data"               # migrations, schema, PII handling
    DEPENDENCY = "dependency"   # requirements, package.json, go.mod
    CONFIGURATION = "configuration"  # env files, app config
    BUSINESS_LOGIC = "business_logic"
    TEST = "test"
    DOCUMENTATION = "documentation"
    UNKNOWN = "unknown"


class ArtifactType(str, Enum):
    DOCKER_IMAGE = "docker_image"
    NPM_PACKAGE = "npm_package"
    PYTHON_WHEEL = "python_wheel"
    BINARY = "binary"
    LAMBDA_ZIP = "lambda_zip"
    HELM_CHART = "helm_chart"
    UNKNOWN = "unknown"


class DeploymentEnvironment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    QA = "qa"
    DR = "dr"
    UNKNOWN = "unknown"


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    ON_PREM = "on_prem"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class FileChange:
    """A single file changed in a commit."""
    path: str
    change_type: str  # added | modified | deleted | renamed
    lines_added: int = 0
    lines_removed: int = 0
    functions_modified: List[str] = field(default_factory=list)
    is_security_relevant: bool = False
    category: str = ChangeCategory.UNKNOWN.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "change_type": self.change_type,
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            "functions_modified": self.functions_modified,
            "is_security_relevant": self.is_security_relevant,
            "category": self.category,
        }


@dataclass
class CodeChange:
    """A git commit with parsed change metadata."""
    change_id: str
    commit_sha: str
    short_sha: str
    author: str
    author_email: str
    message: str
    timestamp: str
    files_changed: List[FileChange] = field(default_factory=list)
    dependencies_added: List[str] = field(default_factory=list)
    dependencies_removed: List[str] = field(default_factory=list)
    risk_level: str = ChangeRisk.NONE.value
    categories: List[str] = field(default_factory=list)
    is_material: bool = False
    pr_number: Optional[str] = None
    branch: Optional[str] = None
    reviewed_by: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "change_id": self.change_id,
            "commit_sha": self.commit_sha,
            "short_sha": self.short_sha,
            "author": self.author,
            "author_email": self.author_email,
            "message": self.message,
            "timestamp": self.timestamp,
            "files_changed": [f.to_dict() for f in self.files_changed],
            "dependencies_added": self.dependencies_added,
            "dependencies_removed": self.dependencies_removed,
            "risk_level": self.risk_level,
            "categories": self.categories,
            "is_material": self.is_material,
            "pr_number": self.pr_number,
            "branch": self.branch,
            "reviewed_by": self.reviewed_by,
        }


@dataclass
class BuildArtifact:
    """A build artifact produced from a commit."""
    artifact_id: str
    artifact_type: str
    name: str
    version: str
    sha256: str
    commit_sha: str
    built_at: str
    builder: str = "unknown"  # CI system: github-actions, jenkins, etc.
    build_url: Optional[str] = None
    size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "name": self.name,
            "version": self.version,
            "sha256": self.sha256,
            "commit_sha": self.commit_sha,
            "built_at": self.built_at,
            "builder": self.builder,
            "build_url": self.build_url,
            "size_bytes": self.size_bytes,
            "metadata": self.metadata,
        }


@dataclass
class Deployment:
    """A deployed artifact in an environment."""
    deployment_id: str
    artifact_id: str
    environment: str
    deployed_at: str
    deployed_by: str
    status: str  # active | rolled_back | terminated
    # K8s
    k8s_namespace: Optional[str] = None
    k8s_deployment: Optional[str] = None
    k8s_pod_count: int = 0
    # Cloud
    cloud_provider: str = CloudProvider.UNKNOWN.value
    cloud_region: Optional[str] = None
    cloud_service: Optional[str] = None
    cloud_instance_ids: List[str] = field(default_factory=list)
    internet_facing: bool = False
    # Rollback
    previous_deployment_id: Optional[str] = None
    rollback_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deployment_id": self.deployment_id,
            "artifact_id": self.artifact_id,
            "environment": self.environment,
            "deployed_at": self.deployed_at,
            "deployed_by": self.deployed_by,
            "status": self.status,
            "k8s_namespace": self.k8s_namespace,
            "k8s_deployment": self.k8s_deployment,
            "k8s_pod_count": self.k8s_pod_count,
            "cloud_provider": self.cloud_provider,
            "cloud_region": self.cloud_region,
            "cloud_service": self.cloud_service,
            "cloud_instance_ids": self.cloud_instance_ids,
            "internet_facing": self.internet_facing,
            "previous_deployment_id": self.previous_deployment_id,
            "rollback_at": self.rollback_at,
        }


@dataclass
class DeveloperRiskProfile:
    """Per-developer risk signal — for education, NOT blame."""
    developer_id: str  # anonymised hash of email
    display_name: str  # first name only or "Dev-XXXX"
    total_commits: int = 0
    security_relevant_commits: int = 0
    material_changes: int = 0
    historical_defect_rate: float = 0.0   # findings per commit
    code_review_coverage: float = 1.0     # fraction of PRs reviewed
    security_training_completed: bool = False
    last_training_date: Optional[str] = None
    risk_score: float = 0.0               # 0.0–1.0
    recommended_training: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "developer_id": self.developer_id,
            "display_name": self.display_name,
            "total_commits": self.total_commits,
            "security_relevant_commits": self.security_relevant_commits,
            "material_changes": self.material_changes,
            "historical_defect_rate": self.historical_defect_rate,
            "code_review_coverage": self.code_review_coverage,
            "security_training_completed": self.security_training_completed,
            "last_training_date": self.last_training_date,
            "risk_score": self.risk_score,
            "recommended_training": self.recommended_training,
        }


@dataclass
class BlastRadius:
    """Impact analysis for a code change."""
    commit_sha: str
    affected_services: List[str] = field(default_factory=list)
    affected_apis: List[str] = field(default_factory=list)
    affected_data_flows: List[str] = field(default_factory=list)
    affected_compliance_controls: List[str] = field(default_factory=list)
    total_blast_score: float = 0.0
    risk_level: str = ChangeRisk.NONE.value
    analysis_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commit_sha": self.commit_sha,
            "affected_services": self.affected_services,
            "affected_apis": self.affected_apis,
            "affected_data_flows": self.affected_data_flows,
            "affected_compliance_controls": self.affected_compliance_controls,
            "total_blast_score": self.total_blast_score,
            "risk_level": self.risk_level,
            "analysis_timestamp": self.analysis_timestamp,
        }


@dataclass
class TimelineEvent:
    """A single event in the provenance timeline."""
    event_id: str
    event_type: str   # code_written | built | deployed | vuln_discovered | exposure_started
    timestamp: str
    actor: str
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "description": self.description,
            "metadata": self.metadata,
        }


@dataclass
class ProvenanceTrace:
    """Full provenance chain for a security finding."""
    trace_id: str
    finding_id: str
    code_change: Optional[CodeChange]
    build_artifact: Optional[BuildArtifact]
    deployment: Optional[Deployment]
    timeline: List[TimelineEvent] = field(default_factory=list)
    developer_profile: Optional[DeveloperRiskProfile] = None
    blast_radius: Optional[BlastRadius] = None
    exposure_duration_hours: float = 0.0
    remediation_priority: str = ChangeRisk.NONE.value
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "finding_id": self.finding_id,
            "code_change": self.code_change.to_dict() if self.code_change else None,
            "build_artifact": self.build_artifact.to_dict() if self.build_artifact else None,
            "deployment": self.deployment.to_dict() if self.deployment else None,
            "timeline": [e.to_dict() for e in self.timeline],
            "developer_profile": self.developer_profile.to_dict() if self.developer_profile else None,
            "blast_radius": self.blast_radius.to_dict() if self.blast_radius else None,
            "exposure_duration_hours": self.exposure_duration_hours,
            "remediation_priority": self.remediation_priority,
            "generated_at": self.generated_at,
        }


# ---------------------------------------------------------------------------
# Material change detection patterns
# ---------------------------------------------------------------------------

# (regex, category, risk_level)
_SECURITY_FILE_PATTERNS: List[Tuple[str, str, str]] = [
    (r"(?i)(auth|authn|authz|authentication|authorization)", ChangeCategory.SECURITY.value, ChangeRisk.HIGH.value),
    (r"(?i)(crypto|encrypt|decrypt|cipher|hash|sign|jwt|token|secret|key)", ChangeCategory.SECURITY.value, ChangeRisk.HIGH.value),
    (r"(?i)(input.valid|sanitiz|escape|xss|csrf|injection)", ChangeCategory.SECURITY.value, ChangeRisk.HIGH.value),
    (r"(?i)(password|credential|passwd|api.key)", ChangeCategory.SECURITY.value, ChangeRisk.CRITICAL.value),
    (r"(?i)(rbac|permission|access.control|acl|role)", ChangeCategory.SECURITY.value, ChangeRisk.HIGH.value),
    (r"(?i)(cors|csp|security.header|hsts|tls|ssl)", ChangeCategory.SECURITY.value, ChangeRisk.MEDIUM.value),
]

_INFRA_FILE_PATTERNS: List[Tuple[str, str, str]] = [
    (r"\.tf$|\.tfvars$|terraform", ChangeCategory.INFRASTRUCTURE.value, ChangeRisk.HIGH.value),
    (r"(?i)(kubernetes|k8s|helm|deployment\.ya?ml|service\.ya?ml|ingress\.ya?ml)", ChangeCategory.INFRASTRUCTURE.value, ChangeRisk.HIGH.value),
    (r"(?i)(dockerfile|\.dockerignore|docker-compose)", ChangeCategory.INFRASTRUCTURE.value, ChangeRisk.MEDIUM.value),
    (r"(?i)(\.github/workflows|\.gitlab-ci|jenkinsfile|\.circleci|\.travis)", ChangeCategory.INFRASTRUCTURE.value, ChangeRisk.HIGH.value),
    (r"(?i)(ansible|puppet|chef|saltstack)", ChangeCategory.INFRASTRUCTURE.value, ChangeRisk.MEDIUM.value),
]

_DATA_FILE_PATTERNS: List[Tuple[str, str, str]] = [
    (r"(?i)(migration|alembic|flyway|liquibase)", ChangeCategory.DATA.value, ChangeRisk.HIGH.value),
    (r"(?i)(schema|model.*\.py|models/.*\.py)", ChangeCategory.DATA.value, ChangeRisk.MEDIUM.value),
    (r"(?i)(pii|gdpr|ccpa|personal.data|user.data)", ChangeCategory.DATA.value, ChangeRisk.HIGH.value),
    (r"(?i)(database|db_|_db\.|\.sql$)", ChangeCategory.DATA.value, ChangeRisk.MEDIUM.value),
]

_DEPENDENCY_FILE_PATTERNS: List[Tuple[str, str, str]] = [
    (r"requirements.*\.txt$|setup\.py$|pyproject\.toml$", ChangeCategory.DEPENDENCY.value, ChangeRisk.HIGH.value),
    (r"package\.json$|package-lock\.json$|yarn\.lock$", ChangeCategory.DEPENDENCY.value, ChangeRisk.HIGH.value),
    (r"go\.mod$|go\.sum$|Cargo\.toml$|Cargo\.lock$", ChangeCategory.DEPENDENCY.value, ChangeRisk.HIGH.value),
    (r"pom\.xml$|build\.gradle$|\.gemspec$|Gemfile", ChangeCategory.DEPENDENCY.value, ChangeRisk.HIGH.value),
]

# Compliance controls that map to file patterns
_COMPLIANCE_MAPPINGS: List[Tuple[str, List[str]]] = [
    ("SOC2-CC6.1", [r"(?i)auth", r"(?i)access.control", r"(?i)rbac"]),
    ("SOC2-CC6.6", [r"(?i)tls|ssl|https|encrypt"]),
    ("SOC2-CC7.2", [r"(?i)log|audit|monitor"]),
    ("PCI-DSS-6.3", [r"(?i)vuln|patch|dependency"]),
    ("PCI-DSS-8.2", [r"(?i)auth|password|credential"]),
    ("GDPR-Art25", [r"(?i)pii|personal.data|privacy"]),
    ("HIPAA-164.312", [r"(?i)encrypt|phi|health.data"]),
    ("NIST-AC-2", [r"(?i)rbac|role|access.control"]),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _anonymise_email(email: str) -> str:
    """Return a stable anonymised ID from an email address."""
    return "dev-" + hashlib.sha256(email.lower().encode()).hexdigest()[:8]


def _display_name(author: str) -> str:
    """Return first name only, or Dev-XXXX if not parseable."""
    parts = author.strip().split()
    if parts:
        return parts[0]
    return "Dev-" + uuid.uuid4().hex[:4].upper()


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------


class CodeToCloudEngine:
    """
    Code-to-Cloud Traceability Engine.

    Maintains in-memory stores for changes, artifacts, and deployments.
    In production, back these with a database (SQLite via PersistentDict pattern).
    """

    # Risk weights for blast-radius scoring
    BLAST_WEIGHTS: Dict[str, float] = {
        "service": 2.0,
        "api": 1.5,
        "data_flow": 3.0,
        "compliance_control": 2.5,
    }

    # Developer risk thresholds
    DEVELOPER_RISK_THRESHOLDS = {
        "defect_rate_high": 0.3,   # >30% commits have findings
        "review_coverage_low": 0.5,  # <50% PRs reviewed
        "security_change_ratio_high": 0.4,  # >40% commits touch security
    }

    def __init__(self) -> None:
        self._lock = Lock()
        # Stores keyed by primary ID
        self._changes: Dict[str, CodeChange] = {}
        self._artifacts: Dict[str, BuildArtifact] = {}
        self._deployments: Dict[str, Deployment] = {}
        # Index: commit_sha → artifact_id
        self._commit_to_artifact: Dict[str, str] = {}
        # Index: artifact_id → list[deployment_id]
        self._artifact_to_deployments: Dict[str, List[str]] = {}
        # Index: finding_id → (commit_sha, artifact_id, deployment_id)
        self._finding_index: Dict[str, Dict[str, Optional[str]]] = {}
        # Developer profiles (keyed by anonymised dev ID)
        self._developer_profiles: Dict[str, DeveloperRiskProfile] = {}

        logger.info("CodeToCloudEngine initialised")

    # ------------------------------------------------------------------
    # 1. Code Change Tracking
    # ------------------------------------------------------------------

    def ingest_commit(
        self,
        commit_sha: str,
        author: str,
        author_email: str,
        message: str,
        files: Optional[List[Dict[str, Any]]] = None,
        pr_number: Optional[str] = None,
        branch: Optional[str] = None,
        reviewed_by: Optional[List[str]] = None,
        timestamp: Optional[str] = None,
    ) -> CodeChange:
        """Parse a git commit and classify its risk."""
        short_sha = commit_sha[:8]
        ts = timestamp or _now_iso()

        parsed_files: List[FileChange] = []
        deps_added: List[str] = []
        deps_removed: List[str] = []
        all_categories: List[str] = []
        max_risk = ChangeRisk.NONE

        for f in (files or []):
            path = f.get("path", "")
            change_type = f.get("change_type", "modified")
            lines_added = f.get("lines_added", 0)
            lines_removed = f.get("lines_removed", 0)
            functions_modified = f.get("functions_modified", [])

            category, risk = self._classify_file(path)
            is_security_relevant = category == ChangeCategory.SECURITY.value

            # Dependency tracking
            if re.search(r"requirements.*\.txt$|package\.json$|go\.mod$|pom\.xml$", path):
                for added in f.get("deps_added", []):
                    deps_added.append(added)
                for removed in f.get("deps_removed", []):
                    deps_removed.append(removed)

            fc = FileChange(
                path=path,
                change_type=change_type,
                lines_added=lines_added,
                lines_removed=lines_removed,
                functions_modified=functions_modified,
                is_security_relevant=is_security_relevant,
                category=category,
            )
            parsed_files.append(fc)
            if category not in all_categories:
                all_categories.append(category)

            # Track highest risk across all files
            risk_order = [ChangeRisk.NONE, ChangeRisk.LOW, ChangeRisk.MEDIUM, ChangeRisk.HIGH, ChangeRisk.CRITICAL]
            if risk_order.index(ChangeRisk(risk)) > risk_order.index(max_risk):
                max_risk = ChangeRisk(risk)

        # Check commit message for security keywords
        if re.search(r"(?i)(fix.*vuln|security|cve-|exploit|patch.*crit)", message):
            if max_risk == ChangeRisk.NONE:
                max_risk = ChangeRisk.MEDIUM

        is_material = max_risk in (ChangeRisk.HIGH, ChangeRisk.CRITICAL) or bool(deps_added or deps_removed)

        change = CodeChange(
            change_id=f"chg-{uuid.uuid4().hex[:12]}",
            commit_sha=commit_sha,
            short_sha=short_sha,
            author=author,
            author_email=author_email,
            message=message,
            timestamp=ts,
            files_changed=parsed_files,
            dependencies_added=deps_added,
            dependencies_removed=deps_removed,
            risk_level=max_risk.value,
            categories=all_categories or [ChangeCategory.UNKNOWN.value],
            is_material=is_material,
            pr_number=pr_number,
            branch=branch,
            reviewed_by=reviewed_by or [],
        )

        with self._lock:
            self._changes[change.change_id] = change
            self._update_developer_profile(change)

        logger.info(
            "commit_ingested",
            sha=short_sha,
            risk=max_risk.value,
            material=is_material,
            files=len(parsed_files),
        )
        return change

    def _classify_file(self, path: str) -> Tuple[str, str]:
        """Return (category, risk_level) for a file path."""
        for pattern, category, risk in _SECURITY_FILE_PATTERNS:
            if re.search(pattern, path):
                return category, risk
        for pattern, category, risk in _INFRA_FILE_PATTERNS:
            if re.search(pattern, path):
                return category, risk
        for pattern, category, risk in _DATA_FILE_PATTERNS:
            if re.search(pattern, path):
                return category, risk
        for pattern, category, risk in _DEPENDENCY_FILE_PATTERNS:
            if re.search(pattern, path):
                return category, risk
        if re.search(r"test_|_test\.|spec\.", path):
            return ChangeCategory.TEST.value, ChangeRisk.LOW.value
        if re.search(r"\.md$|\.rst$|docs/", path):
            return ChangeCategory.DOCUMENTATION.value, ChangeRisk.NONE.value
        if re.search(r"(?i)(config|settings|\.env)", path):
            return ChangeCategory.CONFIGURATION.value, ChangeRisk.MEDIUM.value
        return ChangeCategory.BUSINESS_LOGIC.value, ChangeRisk.LOW.value

    def get_recent_material_changes(self, limit: int = 50) -> List[CodeChange]:
        """Return material changes ordered by timestamp descending."""
        with self._lock:
            changes = [c for c in self._changes.values() if c.is_material]
        changes.sort(key=lambda c: c.timestamp, reverse=True)
        return changes[:limit]

    def get_recent_changes(self, limit: int = 50) -> List[CodeChange]:
        """Return all changes ordered by timestamp descending."""
        with self._lock:
            changes = list(self._changes.values())
        changes.sort(key=lambda c: c.timestamp, reverse=True)
        return changes[:limit]

    # ------------------------------------------------------------------
    # 2. Build Artifact Mapping
    # ------------------------------------------------------------------

    def register_artifact(
        self,
        name: str,
        version: str,
        commit_sha: str,
        artifact_type: str = ArtifactType.DOCKER_IMAGE.value,
        sha256: Optional[str] = None,
        builder: str = "unknown",
        build_url: Optional[str] = None,
        size_bytes: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
        built_at: Optional[str] = None,
    ) -> BuildArtifact:
        """Register a build artifact produced from a commit."""
        artifact_id = f"art-{uuid.uuid4().hex[:12]}"
        computed_sha = sha256 or hashlib.sha256(
            f"{name}:{version}:{commit_sha}".encode()
        ).hexdigest()

        artifact = BuildArtifact(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            name=name,
            version=version,
            sha256=computed_sha,
            commit_sha=commit_sha,
            built_at=built_at or _now_iso(),
            builder=builder,
            build_url=build_url,
            size_bytes=size_bytes,
            metadata=metadata or {},
        )

        with self._lock:
            self._artifacts[artifact_id] = artifact
            self._commit_to_artifact[commit_sha] = artifact_id

        logger.info("artifact_registered", artifact_id=artifact_id, name=name, version=version)
        return artifact

    def get_artifact_for_commit(self, commit_sha: str) -> Optional[BuildArtifact]:
        with self._lock:
            artifact_id = self._commit_to_artifact.get(commit_sha)
            return self._artifacts.get(artifact_id) if artifact_id else None

    # ------------------------------------------------------------------
    # 3. Deployment Tracking
    # ------------------------------------------------------------------

    def register_deployment(
        self,
        artifact_id: str,
        environment: str = DeploymentEnvironment.PRODUCTION.value,
        deployed_by: str = "ci-system",
        k8s_namespace: Optional[str] = None,
        k8s_deployment: Optional[str] = None,
        k8s_pod_count: int = 0,
        cloud_provider: str = CloudProvider.UNKNOWN.value,
        cloud_region: Optional[str] = None,
        cloud_service: Optional[str] = None,
        cloud_instance_ids: Optional[List[str]] = None,
        internet_facing: bool = False,
        previous_deployment_id: Optional[str] = None,
        deployed_at: Optional[str] = None,
    ) -> Deployment:
        """Register a deployment of an artifact to an environment."""
        deployment_id = f"dep-{uuid.uuid4().hex[:12]}"

        deployment = Deployment(
            deployment_id=deployment_id,
            artifact_id=artifact_id,
            environment=environment,
            deployed_at=deployed_at or _now_iso(),
            deployed_by=deployed_by,
            status="active",
            k8s_namespace=k8s_namespace,
            k8s_deployment=k8s_deployment,
            k8s_pod_count=k8s_pod_count,
            cloud_provider=cloud_provider,
            cloud_region=cloud_region,
            cloud_service=cloud_service,
            cloud_instance_ids=cloud_instance_ids or [],
            internet_facing=internet_facing,
            previous_deployment_id=previous_deployment_id,
        )

        with self._lock:
            self._deployments[deployment_id] = deployment
            self._artifact_to_deployments.setdefault(artifact_id, []).append(deployment_id)

        logger.info(
            "deployment_registered",
            deployment_id=deployment_id,
            env=environment,
            internet_facing=internet_facing,
        )
        return deployment

    def get_deployments_for_artifact(self, artifact_id: str) -> List[Deployment]:
        with self._lock:
            dep_ids = self._artifact_to_deployments.get(artifact_id, [])
            return [self._deployments[d] for d in dep_ids if d in self._deployments]

    def get_all_deployments(self, limit: int = 100) -> List[Deployment]:
        with self._lock:
            deps = list(self._deployments.values())
        deps.sort(key=lambda d: d.deployed_at, reverse=True)
        return deps[:limit]

    # ------------------------------------------------------------------
    # 4. Runtime Correlation — index a finding against the chain
    # ------------------------------------------------------------------

    def index_finding(
        self,
        finding_id: str,
        commit_sha: Optional[str] = None,
        artifact_id: Optional[str] = None,
        deployment_id: Optional[str] = None,
    ) -> None:
        """Associate a runtime finding with its provenance chain entries."""
        with self._lock:
            self._finding_index[finding_id] = {
                "commit_sha": commit_sha,
                "artifact_id": artifact_id,
                "deployment_id": deployment_id,
            }
        logger.info("finding_indexed", finding_id=finding_id, commit_sha=commit_sha)

    # ------------------------------------------------------------------
    # 5. Blast Radius Analysis
    # ------------------------------------------------------------------

    def compute_blast_radius(self, commit_sha: str) -> BlastRadius:
        """Compute blast radius for a commit based on its file changes."""
        with self._lock:
            change = next(
                (c for c in self._changes.values() if c.commit_sha == commit_sha), None
            )

        blast = BlastRadius(commit_sha=commit_sha)

        if not change:
            return blast

        # Determine affected services from file paths
        services: set = set()
        apis: set = set()
        data_flows: set = set()
        compliance_controls: set = set()

        for fc in change.files_changed:
            # Service detection from path segments
            parts = fc.path.split("/")
            if len(parts) >= 2:
                top = parts[0]
                services.add(top)

            # API detection
            if re.search(r"(?i)(router|endpoint|api|view|controller)", fc.path):
                apis.add(fc.path)

            # Data flow detection
            if fc.category == ChangeCategory.DATA.value:
                data_flows.add(fc.path)

            # Compliance mapping
            for control, patterns in _COMPLIANCE_MAPPINGS:
                for pat in patterns:
                    if re.search(pat, fc.path) or re.search(pat, change.message):
                        compliance_controls.add(control)
                        break

        blast.affected_services = sorted(services)
        blast.affected_apis = sorted(apis)
        blast.affected_data_flows = sorted(data_flows)
        blast.affected_compliance_controls = sorted(compliance_controls)

        # Score
        score = (
            len(services) * self.BLAST_WEIGHTS["service"]
            + len(apis) * self.BLAST_WEIGHTS["api"]
            + len(data_flows) * self.BLAST_WEIGHTS["data_flow"]
            + len(compliance_controls) * self.BLAST_WEIGHTS["compliance_control"]
        )
        blast.total_blast_score = round(score, 2)

        # Risk level from score
        if score >= 20:
            blast.risk_level = ChangeRisk.CRITICAL.value
        elif score >= 10:
            blast.risk_level = ChangeRisk.HIGH.value
        elif score >= 5:
            blast.risk_level = ChangeRisk.MEDIUM.value
        elif score > 0:
            blast.risk_level = ChangeRisk.LOW.value
        else:
            blast.risk_level = ChangeRisk.NONE.value

        return blast

    # ------------------------------------------------------------------
    # 6. Developer Risk Profile
    # ------------------------------------------------------------------

    def _update_developer_profile(self, change: CodeChange) -> None:
        """Update developer profile from a newly ingested commit (called under lock)."""
        dev_id = _anonymise_email(change.author_email)
        profile = self._developer_profiles.get(dev_id)
        if profile is None:
            profile = DeveloperRiskProfile(
                developer_id=dev_id,
                display_name=_display_name(change.author),
            )
            self._developer_profiles[dev_id] = profile

        profile.total_commits += 1

        has_security = any(
            fc.is_security_relevant for fc in change.files_changed
        )
        if has_security:
            profile.security_relevant_commits += 1
        if change.is_material:
            profile.material_changes += 1

        # Review coverage: if no reviewers, this PR is unreviewed
        if change.pr_number and not change.reviewed_by:
            # Exponential moving average of unreviewed ratio
            profile.code_review_coverage = max(
                0.0,
                profile.code_review_coverage * 0.9,
            )

        self._recalculate_risk_score(profile)

    def _recalculate_risk_score(self, profile: DeveloperRiskProfile) -> None:
        """Recompute composite risk score 0.0–1.0 (higher = more education needed)."""
        score = 0.0

        if profile.total_commits > 0:
            sec_ratio = profile.security_relevant_commits / profile.total_commits
            if sec_ratio > self.DEVELOPER_RISK_THRESHOLDS["security_change_ratio_high"]:
                score += 0.3

        defect_rate = profile.historical_defect_rate
        if defect_rate > self.DEVELOPER_RISK_THRESHOLDS["defect_rate_high"]:
            score += 0.4

        if profile.code_review_coverage < self.DEVELOPER_RISK_THRESHOLDS["review_coverage_low"]:
            score += 0.2

        if not profile.security_training_completed:
            score += 0.1

        profile.risk_score = round(min(score, 1.0), 3)

        # Recommended training
        training: List[str] = []
        if profile.security_relevant_commits > 5 and not profile.security_training_completed:
            training.append("secure-coding-fundamentals")
        if defect_rate > 0.2:
            training.append("code-review-best-practices")
        if profile.code_review_coverage < 0.7:
            training.append("peer-review-process")
        profile.recommended_training = training

    def record_finding_for_developer(self, author_email: str) -> None:
        """Record that a finding was attributed to a developer's commit."""
        dev_id = _anonymise_email(author_email)
        with self._lock:
            profile = self._developer_profiles.get(dev_id)
            if profile and profile.total_commits > 0:
                profile.historical_defect_rate = min(
                    1.0,
                    profile.historical_defect_rate + (1.0 / profile.total_commits),
                )
                self._recalculate_risk_score(profile)

    def get_developer_profiles(self) -> List[DeveloperRiskProfile]:
        with self._lock:
            return list(self._developer_profiles.values())

    # ------------------------------------------------------------------
    # 7. Timeline Reconstruction
    # ------------------------------------------------------------------

    def reconstruct_timeline(
        self,
        finding_id: str,
        discovered_at: Optional[str] = None,
    ) -> List[TimelineEvent]:
        """Reconstruct full timeline for a finding from its provenance chain."""
        events: List[TimelineEvent] = []

        with self._lock:
            index = self._finding_index.get(finding_id, {})
            commit_sha = index.get("commit_sha")
            artifact_id = index.get("artifact_id")
            deployment_id = index.get("deployment_id")

            change = (
                next((c for c in self._changes.values() if c.commit_sha == commit_sha), None)
                if commit_sha else None
            )
            artifact = self._artifacts.get(artifact_id) if artifact_id else None
            deployment = self._deployments.get(deployment_id) if deployment_id else None

        if change:
            events.append(TimelineEvent(
                event_id=f"evt-{uuid.uuid4().hex[:8]}",
                event_type="code_written",
                timestamp=change.timestamp,
                actor=change.author,
                description=f"Code committed: {change.message[:80]}",
                metadata={"commit_sha": change.commit_sha, "files": len(change.files_changed)},
            ))

        if artifact:
            events.append(TimelineEvent(
                event_id=f"evt-{uuid.uuid4().hex[:8]}",
                event_type="built",
                timestamp=artifact.built_at,
                actor=artifact.builder,
                description=f"Artifact built: {artifact.name}:{artifact.version}",
                metadata={"artifact_id": artifact.artifact_id, "sha256": artifact.sha256[:16]},
            ))

        if deployment:
            events.append(TimelineEvent(
                event_id=f"evt-{uuid.uuid4().hex[:8]}",
                event_type="deployed",
                timestamp=deployment.deployed_at,
                actor=deployment.deployed_by,
                description=f"Deployed to {deployment.environment}",
                metadata={
                    "deployment_id": deployment.deployment_id,
                    "environment": deployment.environment,
                    "internet_facing": deployment.internet_facing,
                },
            ))

        disc_ts = discovered_at or _now_iso()
        events.append(TimelineEvent(
            event_id=f"evt-{uuid.uuid4().hex[:8]}",
            event_type="vuln_discovered",
            timestamp=disc_ts,
            actor="scanner",
            description=f"Finding {finding_id} discovered",
            metadata={"finding_id": finding_id},
        ))

        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)
        return events

    # ------------------------------------------------------------------
    # 8. Full Provenance Trace
    # ------------------------------------------------------------------

    def trace_finding(
        self,
        finding_id: str,
        discovered_at: Optional[str] = None,
    ) -> ProvenanceTrace:
        """Reconstruct full code-to-cloud provenance for a security finding."""
        t0 = time.monotonic()

        with self._lock:
            index = self._finding_index.get(finding_id, {})
            commit_sha = index.get("commit_sha")
            artifact_id = index.get("artifact_id")
            deployment_id = index.get("deployment_id")

            change = (
                next((c for c in self._changes.values() if c.commit_sha == commit_sha), None)
                if commit_sha else None
            )
            artifact = self._artifacts.get(artifact_id) if artifact_id else None
            deployment = self._deployments.get(deployment_id) if deployment_id else None
            dev_profile = None
            if change:
                dev_id = _anonymise_email(change.author_email)
                dev_profile = self._developer_profiles.get(dev_id)

        # Blast radius for the commit
        blast = None
        if change:
            blast = self.compute_blast_radius(change.commit_sha)

        # Timeline
        timeline = self.reconstruct_timeline(finding_id, discovered_at)

        # Exposure duration
        exposure_hours = 0.0
        if deployment and deployment.deployed_at:
            try:
                dep_dt = datetime.fromisoformat(deployment.deployed_at.replace("Z", "+00:00"))
                disc_dt = datetime.fromisoformat(
                    (discovered_at or _now_iso()).replace("Z", "+00:00")
                )
                exposure_hours = max(0.0, (disc_dt - dep_dt).total_seconds() / 3600)
            except (ValueError, TypeError):
                pass

        # Remediation priority
        priority = self._compute_remediation_priority(change, deployment, blast)

        trace = ProvenanceTrace(
            trace_id=f"trace-{uuid.uuid4().hex[:12]}",
            finding_id=finding_id,
            code_change=change,
            build_artifact=artifact,
            deployment=deployment,
            timeline=timeline,
            developer_profile=dev_profile,
            blast_radius=blast,
            exposure_duration_hours=round(exposure_hours, 2),
            remediation_priority=priority,
        )

        logger.info(
            "trace_generated",
            finding_id=finding_id,
            has_change=change is not None,
            has_artifact=artifact is not None,
            has_deployment=deployment is not None,
            duration_ms=round((time.monotonic() - t0) * 1000, 1),
        )
        return trace

    def _compute_remediation_priority(
        self,
        change: Optional[CodeChange],
        deployment: Optional[Deployment],
        blast: Optional[BlastRadius],
    ) -> str:
        score = 0

        if deployment and deployment.internet_facing:
            score += 3
        if blast and blast.risk_level == ChangeRisk.CRITICAL.value:
            score += 3
        elif blast and blast.risk_level == ChangeRisk.HIGH.value:
            score += 2
        if change and change.risk_level in (ChangeRisk.CRITICAL.value, ChangeRisk.HIGH.value):
            score += 2
        if blast and len(blast.affected_compliance_controls) > 2:
            score += 1

        if score >= 6:
            return ChangeRisk.CRITICAL.value
        elif score >= 4:
            return ChangeRisk.HIGH.value
        elif score >= 2:
            return ChangeRisk.MEDIUM.value
        elif score >= 1:
            return ChangeRisk.LOW.value
        return ChangeRisk.NONE.value

    # ------------------------------------------------------------------
    # Webhook ingestion (real-time git events)
    # ------------------------------------------------------------------

    def process_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a GitHub/GitLab webhook payload.
        Supports push events (commits) and pull_request events.
        """
        event_type = payload.get("event_type", payload.get("object_kind", "push"))
        processed: List[str] = []

        if event_type in ("push", "push_hook"):
            commits = payload.get("commits", [])
            branch = payload.get("ref", "").replace("refs/heads/", "")
            for commit in commits:
                sha = commit.get("id", commit.get("sha", ""))
                if not sha:
                    continue
                files: List[Dict[str, Any]] = []
                for path in commit.get("added", []):
                    files.append({"path": path, "change_type": "added"})
                for path in commit.get("modified", []):
                    files.append({"path": path, "change_type": "modified"})
                for path in commit.get("removed", []):
                    files.append({"path": path, "change_type": "deleted"})

                author = commit.get("author", {})
                change = self.ingest_commit(
                    commit_sha=sha,
                    author=author.get("name", "unknown"),
                    author_email=author.get("email", "unknown@unknown"),
                    message=commit.get("message", ""),
                    files=files,
                    branch=branch,
                    timestamp=commit.get("timestamp"),
                )
                processed.append(change.change_id)

        elif event_type in ("pull_request", "merge_request"):
            pr = payload.get("pull_request", payload.get("object_attributes", {}))
            sha = pr.get("head", {}).get("sha") or pr.get("last_commit", {}).get("id")
            if sha:
                change = self.ingest_commit(
                    commit_sha=sha,
                    author=pr.get("user", {}).get("login", "unknown"),
                    author_email=pr.get("user", {}).get("email", "unknown@unknown"),
                    message=pr.get("title", ""),
                    pr_number=str(pr.get("number", pr.get("iid", ""))),
                    branch=pr.get("head", {}).get("ref"),
                )
                processed.append(change.change_id)

        return {
            "event_type": event_type,
            "processed_changes": processed,
            "count": len(processed),
        }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_instance: Optional[CodeToCloudEngine] = None
_engine_lock = Lock()


def get_engine() -> CodeToCloudEngine:
    """Return the process-wide CodeToCloudEngine singleton."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = CodeToCloudEngine()
    return _engine_instance
