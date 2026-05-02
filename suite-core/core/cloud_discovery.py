"""Multi-Cloud Asset Discovery — AWS, Azure, GCP inventory.

Discovers and inventories assets across major cloud providers with realistic
mock data for environments where live credentials are unavailable.

Usage:
    from core.cloud_discovery import CloudDiscovery, get_cloud_discovery
    discovery = get_cloud_discovery()
    assets = discovery.discover_all("org-1")
    inventory = discovery.get_asset_inventory("org-1")
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_CLOUD_DISCOVERY_DB", ".fixops_data/cloud_discovery.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CloudAssetType(str, Enum):
    VM = "vm"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    DATABASE = "database"
    STORAGE = "storage"
    NETWORK = "network"
    IAM = "iam"
    DNS = "dns"
    CDN = "cdn"
    API_GATEWAY = "api_gateway"
    QUEUE = "queue"
    CACHE = "cache"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class CloudAsset(BaseModel):
    id: str = Field(default_factory=lambda: f"ca-{uuid.uuid4().hex[:12]}")
    provider: str  # aws | azure | gcp
    asset_type: CloudAssetType
    name: str
    region: str
    account_id: str
    resource_id: str
    tags: Dict[str, str] = Field(default_factory=dict)
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    risk_score: float = 0.0
    org_id: str = "default"


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------


class _CloudDiscoveryDB:
    """SQLite persistence for discovered cloud assets."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        dir_part = os.path.dirname(db_path)
        if dir_part:
            os.makedirs(dir_part, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS cloud_assets (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    tags TEXT NOT NULL DEFAULT '{}',
                    public_ip TEXT,
                    private_ip TEXT,
                    created_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    risk_score REAL NOT NULL DEFAULT 0.0,
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ca_org ON cloud_assets(org_id);
                CREATE INDEX IF NOT EXISTS idx_ca_provider ON cloud_assets(provider);
                CREATE INDEX IF NOT EXISTS idx_ca_type ON cloud_assets(asset_type);
                CREATE INDEX IF NOT EXISTS idx_ca_region ON cloud_assets(region);
                CREATE INDEX IF NOT EXISTS idx_ca_account ON cloud_assets(account_id);
                CREATE INDEX IF NOT EXISTS idx_ca_last_seen ON cloud_assets(last_seen);

                CREATE TABLE IF NOT EXISTS cmdb_assets (
                    resource_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    PRIMARY KEY (resource_id, org_id)
                );
                CREATE INDEX IF NOT EXISTS idx_cmdb_org ON cmdb_assets(org_id);
            """)
            self._conn.commit()

    def upsert_asset(self, asset: CloudAsset) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO cloud_assets
                   (id, provider, asset_type, name, region, account_id, resource_id,
                    tags, public_ip, private_ip, created_at, last_seen, risk_score, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    asset.id, asset.provider, asset.asset_type.value,
                    asset.name, asset.region, asset.account_id, asset.resource_id,
                    json.dumps(asset.tags), asset.public_ip, asset.private_ip,
                    asset.created_at, asset.last_seen, asset.risk_score, asset.org_id,
                ),
            )
            self._conn.commit()

    def upsert_many(self, assets: List[CloudAsset]) -> None:
        with self._lock:
            self._conn.executemany(
                """INSERT OR REPLACE INTO cloud_assets
                   (id, provider, asset_type, name, region, account_id, resource_id,
                    tags, public_ip, private_ip, created_at, last_seen, risk_score, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        a.id, a.provider, a.asset_type.value,
                        a.name, a.region, a.account_id, a.resource_id,
                        json.dumps(a.tags), a.public_ip, a.private_ip,
                        a.created_at, a.last_seen, a.risk_score, a.org_id,
                    )
                    for a in assets
                ],
            )
            self._conn.commit()

    def list_assets(
        self,
        org_id: str,
        provider: Optional[str] = None,
        asset_type: Optional[str] = None,
        region: Optional[str] = None,
        account_id: Optional[str] = None,
    ) -> List[CloudAsset]:
        query = "SELECT * FROM cloud_assets WHERE org_id = ?"
        params: List[Any] = [org_id]
        if provider:
            query += " AND provider = ?"
            params.append(provider)
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        if region:
            query += " AND region = ?"
            params.append(region)
        if account_id:
            query += " AND account_id = ?"
            params.append(account_id)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def list_public_assets(self, org_id: str) -> List[CloudAsset]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM cloud_assets WHERE org_id = ? AND public_ip IS NOT NULL AND public_ip != ''",
                (org_id,),
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def list_new_assets_since(self, org_id: str, since: str) -> List[CloudAsset]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM cloud_assets WHERE org_id = ? AND created_at >= ?",
                (org_id, since),
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def list_removed_assets_since(self, org_id: str, since: str) -> List[CloudAsset]:
        """Assets not seen since the cutoff date (last_seen < since)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM cloud_assets WHERE org_id = ? AND last_seen < ?",
                (org_id, since),
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def get_cmdb_resource_ids(self, org_id: str) -> set:
        with self._lock:
            rows = self._conn.execute(
                "SELECT resource_id FROM cmdb_assets WHERE org_id = ?", (org_id,)
            ).fetchall()
        return {r[0] for r in rows}

    def register_cmdb_asset(self, resource_id: str, org_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO cmdb_assets (resource_id, org_id) VALUES (?, ?)",
                (resource_id, org_id),
            )
            self._conn.commit()

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM cloud_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_provider = {
                r[0]: r[1]
                for r in self._conn.execute(
                    "SELECT provider, COUNT(*) FROM cloud_assets WHERE org_id = ? GROUP BY provider",
                    (org_id,),
                ).fetchall()
            }

            by_type = {
                r[0]: r[1]
                for r in self._conn.execute(
                    "SELECT asset_type, COUNT(*) FROM cloud_assets WHERE org_id = ? GROUP BY asset_type",
                    (org_id,),
                ).fetchall()
            }

            by_region = {
                r[0]: r[1]
                for r in self._conn.execute(
                    "SELECT region, COUNT(*) FROM cloud_assets WHERE org_id = ? GROUP BY region",
                    (org_id,),
                ).fetchall()
            }

            public_count = self._conn.execute(
                "SELECT COUNT(*) FROM cloud_assets WHERE org_id = ? AND public_ip IS NOT NULL AND public_ip != ''",
                (org_id,),
            ).fetchone()[0]

            avg_risk = self._conn.execute(
                "SELECT AVG(risk_score) FROM cloud_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0] or 0.0

        return {
            "total": total,
            "by_provider": by_provider,
            "by_type": by_type,
            "by_region": by_region,
            "public_count": public_count,
            "avg_risk_score": round(avg_risk, 2),
        }

    def _row_to_asset(self, row: tuple) -> CloudAsset:
        (
            id_, provider, asset_type, name, region, account_id, resource_id,
            tags, public_ip, private_ip, created_at, last_seen, risk_score, org_id,
        ) = row
        return CloudAsset(
            id=id_,
            provider=provider,
            asset_type=CloudAssetType(asset_type),
            name=name,
            region=region,
            account_id=account_id,
            resource_id=resource_id,
            tags=json.loads(tags) if tags else {},
            public_ip=public_ip,
            private_ip=private_ip,
            created_at=created_at,
            last_seen=last_seen,
            risk_score=risk_score,
            org_id=org_id,
        )


# ---------------------------------------------------------------------------
# Mock data builders
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _build_aws_assets(org_id: str) -> List[CloudAsset]:
    account = "123456789012"
    assets = [
        # VMs (EC2 instances)
        CloudAsset(provider="aws", asset_type=CloudAssetType.VM, name="prod-web-01",
                   region="us-east-1", account_id=account, resource_id="i-0a1b2c3d4e5f60001",
                   tags={"env": "production", "team": "platform"}, public_ip="54.160.10.1",
                   private_ip="10.0.1.10", risk_score=6.5, org_id=org_id,
                   created_at=_days_ago(120), last_seen=_now()),
        CloudAsset(provider="aws", asset_type=CloudAssetType.VM, name="prod-web-02",
                   region="us-east-1", account_id=account, resource_id="i-0a1b2c3d4e5f60002",
                   tags={"env": "production", "team": "platform"}, public_ip="54.160.10.2",
                   private_ip="10.0.1.11", risk_score=6.5, org_id=org_id,
                   created_at=_days_ago(120), last_seen=_now()),
        CloudAsset(provider="aws", asset_type=CloudAssetType.VM, name="prod-api-01",
                   region="us-west-2", account_id=account, resource_id="i-0a1b2c3d4e5f60003",
                   tags={"env": "production", "team": "backend"}, public_ip=None,
                   private_ip="10.0.2.10", risk_score=4.2, org_id=org_id,
                   created_at=_days_ago(90), last_seen=_now()),
        CloudAsset(provider="aws", asset_type=CloudAssetType.VM, name="staging-worker-01",
                   region="us-east-1", account_id=account, resource_id="i-0a1b2c3d4e5f60004",
                   tags={"env": "staging", "team": "backend"}, public_ip=None,
                   private_ip="10.1.1.10", risk_score=2.1, org_id=org_id,
                   created_at=_days_ago(60), last_seen=_now()),
        # Containers (ECS / EKS)
        CloudAsset(provider="aws", asset_type=CloudAssetType.CONTAINER, name="ecs-prod-api",
                   region="us-east-1", account_id=account, resource_id="arn:aws:ecs:us-east-1:123456789012:service/prod-api",
                   tags={"env": "production", "framework": "fastapi"}, public_ip=None,
                   private_ip="10.0.3.20", risk_score=5.0, org_id=org_id,
                   created_at=_days_ago(45), last_seen=_now()),
        CloudAsset(provider="aws", asset_type=CloudAssetType.CONTAINER, name="eks-worker-pool",
                   region="us-west-2", account_id=account, resource_id="arn:aws:eks:us-west-2:123456789012:nodegroup/workers",
                   tags={"env": "production", "k8s": "true"}, public_ip=None,
                   private_ip="10.0.4.0", risk_score=4.8, org_id=org_id,
                   created_at=_days_ago(30), last_seen=_now()),
        # Serverless (Lambda)
        CloudAsset(provider="aws", asset_type=CloudAssetType.SERVERLESS, name="lambda-intake-processor",
                   region="us-east-1", account_id=account, resource_id="arn:aws:lambda:us-east-1:123456789012:function:intake-processor",
                   tags={"env": "production", "runtime": "python3.11"}, risk_score=3.0, org_id=org_id,
                   created_at=_days_ago(75), last_seen=_now()),
        CloudAsset(provider="aws", asset_type=CloudAssetType.SERVERLESS, name="lambda-alert-fanout",
                   region="us-east-1", account_id=account, resource_id="arn:aws:lambda:us-east-1:123456789012:function:alert-fanout",
                   tags={"env": "production", "runtime": "python3.11"}, risk_score=2.5, org_id=org_id,
                   created_at=_days_ago(60), last_seen=_now()),
        # Databases (RDS)
        CloudAsset(provider="aws", asset_type=CloudAssetType.DATABASE, name="rds-prod-postgres",
                   region="us-east-1", account_id=account, resource_id="arn:aws:rds:us-east-1:123456789012:db:prod-postgres",
                   tags={"env": "production", "engine": "postgres14"}, private_ip="10.0.5.10",
                   risk_score=8.0, org_id=org_id, created_at=_days_ago(200), last_seen=_now()),
        CloudAsset(provider="aws", asset_type=CloudAssetType.DATABASE, name="rds-analytics-mysql",
                   region="us-west-2", account_id=account, resource_id="arn:aws:rds:us-west-2:123456789012:db:analytics-mysql",
                   tags={"env": "production", "engine": "mysql8"}, private_ip="10.0.5.11",
                   risk_score=7.5, org_id=org_id, created_at=_days_ago(150), last_seen=_now()),
        # Storage (S3)
        CloudAsset(provider="aws", asset_type=CloudAssetType.STORAGE, name="s3-prod-assets",
                   region="us-east-1", account_id=account, resource_id="arn:aws:s3:::prod-assets-aldeci",
                   tags={"env": "production", "public": "false"}, risk_score=5.5, org_id=org_id,
                   created_at=_days_ago(365), last_seen=_now()),
        CloudAsset(provider="aws", asset_type=CloudAssetType.STORAGE, name="s3-backups",
                   region="us-east-1", account_id=account, resource_id="arn:aws:s3:::aldeci-backups-prod",
                   tags={"env": "production", "encrypted": "true"}, risk_score=3.0, org_id=org_id,
                   created_at=_days_ago(300), last_seen=_now()),
        # Network (VPC / ELB)
        CloudAsset(provider="aws", asset_type=CloudAssetType.NETWORK, name="elb-prod-external",
                   region="us-east-1", account_id=account, resource_id="arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-external",
                   tags={"env": "production"}, public_ip="52.20.100.1",
                   risk_score=6.0, org_id=org_id, created_at=_days_ago(180), last_seen=_now()),
        # IAM
        CloudAsset(provider="aws", asset_type=CloudAssetType.IAM, name="iam-role-prod-ec2",
                   region="global", account_id=account, resource_id="arn:aws:iam::123456789012:role/prod-ec2-role",
                   tags={"env": "production"}, risk_score=7.0, org_id=org_id,
                   created_at=_days_ago(365), last_seen=_now()),
        # Queue (SQS)
        CloudAsset(provider="aws", asset_type=CloudAssetType.QUEUE, name="sqs-findings-queue",
                   region="us-east-1", account_id=account, resource_id="arn:aws:sqs:us-east-1:123456789012:findings-queue",
                   tags={"env": "production"}, risk_score=2.0, org_id=org_id,
                   created_at=_days_ago(90), last_seen=_now()),
        # Cache (ElastiCache)
        CloudAsset(provider="aws", asset_type=CloudAssetType.CACHE, name="elasticache-prod-redis",
                   region="us-east-1", account_id=account, resource_id="arn:aws:elasticache:us-east-1:123456789012:cluster:prod-redis",
                   tags={"env": "production", "engine": "redis7"}, private_ip="10.0.6.10",
                   risk_score=4.0, org_id=org_id, created_at=_days_ago(120), last_seen=_now()),
        # API Gateway
        CloudAsset(provider="aws", asset_type=CloudAssetType.API_GATEWAY, name="apigw-prod-v1",
                   region="us-east-1", account_id=account, resource_id="arn:aws:apigateway:us-east-1::/restapis/abc12345",
                   tags={"env": "production", "stage": "v1"}, public_ip="54.160.20.1",
                   risk_score=5.5, org_id=org_id, created_at=_days_ago(200), last_seen=_now()),
        # CDN (CloudFront)
        CloudAsset(provider="aws", asset_type=CloudAssetType.CDN, name="cloudfront-prod",
                   region="global", account_id=account, resource_id="arn:aws:cloudfront::123456789012:distribution/EDFDVBD6EXAMPLE",
                   tags={"env": "production"}, public_ip="13.32.100.1",
                   risk_score=3.5, org_id=org_id, created_at=_days_ago(365), last_seen=_now()),
        # DNS (Route53)
        CloudAsset(provider="aws", asset_type=CloudAssetType.DNS, name="route53-aldeci-io",
                   region="global", account_id=account, resource_id="arn:aws:route53:::hostedzone/Z1EXAMPLE",
                   tags={"env": "production"}, risk_score=4.0, org_id=org_id,
                   created_at=_days_ago(500), last_seen=_now()),
        # Extra VM for drift testing
        CloudAsset(provider="aws", asset_type=CloudAssetType.VM, name="prod-bastion",
                   region="us-east-1", account_id=account, resource_id="i-0a1b2c3d4e5f60099",
                   tags={"env": "production", "role": "bastion"}, public_ip="54.160.99.1",
                   private_ip="10.0.1.99", risk_score=9.0, org_id=org_id,
                   created_at=_days_ago(5), last_seen=_now()),
    ]
    return assets


def _build_azure_assets(org_id: str) -> List[CloudAsset]:
    subscription = "sub-azure-0001-prod"
    assets = [
        # VMs
        CloudAsset(provider="azure", asset_type=CloudAssetType.VM, name="az-prod-vm-001",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/az-prod-vm-001",
                   tags={"env": "production", "team": "platform"}, public_ip="20.40.10.1",
                   private_ip="10.0.10.10", risk_score=6.0, org_id=org_id,
                   created_at=_days_ago(100), last_seen=_now()),
        CloudAsset(provider="azure", asset_type=CloudAssetType.VM, name="az-prod-vm-002",
                   region="westeurope", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/eu-rg/providers/Microsoft.Compute/virtualMachines/az-prod-vm-002",
                   tags={"env": "production", "region": "eu"}, public_ip=None,
                   private_ip="10.1.10.10", risk_score=5.5, org_id=org_id,
                   created_at=_days_ago(80), last_seen=_now()),
        CloudAsset(provider="azure", asset_type=CloudAssetType.VM, name="az-dev-vm-001",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/dev-rg/providers/Microsoft.Compute/virtualMachines/az-dev-vm-001",
                   tags={"env": "development"}, public_ip=None,
                   private_ip="10.2.10.10", risk_score=2.0, org_id=org_id,
                   created_at=_days_ago(30), last_seen=_now()),
        # Containers (AKS)
        CloudAsset(provider="azure", asset_type=CloudAssetType.CONTAINER, name="aks-prod-cluster",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.ContainerService/managedClusters/aks-prod",
                   tags={"env": "production", "k8s": "1.28"}, risk_score=5.2, org_id=org_id,
                   created_at=_days_ago(60), last_seen=_now()),
        CloudAsset(provider="azure", asset_type=CloudAssetType.CONTAINER, name="acr-prod-registry",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.ContainerRegistry/registries/aldeciprod",
                   tags={"env": "production"}, risk_score=4.0, org_id=org_id,
                   created_at=_days_ago(90), last_seen=_now()),
        # Serverless (Azure Functions)
        CloudAsset(provider="azure", asset_type=CloudAssetType.SERVERLESS, name="func-intake-processor",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.Web/sites/func-intake-processor",
                   tags={"env": "production", "runtime": "python3.11"}, risk_score=2.8, org_id=org_id,
                   created_at=_days_ago(45), last_seen=_now()),
        # Databases (Azure SQL / CosmosDB)
        CloudAsset(provider="azure", asset_type=CloudAssetType.DATABASE, name="sql-prod-findings",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/aldeci-sql/databases/findings",
                   tags={"env": "production", "engine": "azuresql"}, private_ip="10.0.20.10",
                   risk_score=8.5, org_id=org_id, created_at=_days_ago(200), last_seen=_now()),
        CloudAsset(provider="azure", asset_type=CloudAssetType.DATABASE, name="cosmos-prod-events",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.DocumentDB/databaseAccounts/aldeci-cosmos",
                   tags={"env": "production", "engine": "cosmosdb"}, risk_score=7.0, org_id=org_id,
                   created_at=_days_ago(150), last_seen=_now()),
        # Storage (Blob)
        CloudAsset(provider="azure", asset_type=CloudAssetType.STORAGE, name="blob-prod-artifacts",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/aldeciprodartifacts",
                   tags={"env": "production", "tier": "cool"}, risk_score=4.5, org_id=org_id,
                   created_at=_days_ago(300), last_seen=_now()),
        # Network (Azure Load Balancer / VNet)
        CloudAsset(provider="azure", asset_type=CloudAssetType.NETWORK, name="alb-prod-external",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.Network/loadBalancers/alb-prod",
                   tags={"env": "production"}, public_ip="20.40.100.1",
                   risk_score=5.8, org_id=org_id, created_at=_days_ago(180), last_seen=_now()),
        # IAM (Azure AD Service Principal)
        CloudAsset(provider="azure", asset_type=CloudAssetType.IAM, name="sp-prod-aks",
                   region="global", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/servicePrincipals/sp-prod-aks",
                   tags={"env": "production"}, risk_score=7.5, org_id=org_id,
                   created_at=_days_ago(365), last_seen=_now()),
        # Queue (Service Bus)
        CloudAsset(provider="azure", asset_type=CloudAssetType.QUEUE, name="sb-prod-findings",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.ServiceBus/namespaces/aldeci-sb/queues/findings",
                   tags={"env": "production"}, risk_score=2.5, org_id=org_id,
                   created_at=_days_ago(90), last_seen=_now()),
        # Cache (Azure Cache for Redis)
        CloudAsset(provider="azure", asset_type=CloudAssetType.CACHE, name="redis-prod-cache",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.Cache/Redis/aldeci-redis",
                   tags={"env": "production"}, private_ip="10.0.30.10",
                   risk_score=3.8, org_id=org_id, created_at=_days_ago(120), last_seen=_now()),
        # API Management
        CloudAsset(provider="azure", asset_type=CloudAssetType.API_GATEWAY, name="apim-prod",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.ApiManagement/service/aldeci-apim",
                   tags={"env": "production"}, public_ip="20.40.200.1",
                   risk_score=6.2, org_id=org_id, created_at=_days_ago(240), last_seen=_now()),
        # CDN (Azure CDN)
        CloudAsset(provider="azure", asset_type=CloudAssetType.CDN, name="cdn-prod-assets",
                   region="global", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.Cdn/profiles/aldeci-cdn",
                   tags={"env": "production"}, public_ip="104.40.10.1",
                   risk_score=3.0, org_id=org_id, created_at=_days_ago(365), last_seen=_now()),
        # DNS (Azure DNS)
        CloudAsset(provider="azure", asset_type=CloudAssetType.DNS, name="dns-aldeci-io",
                   region="global", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.Network/dnsZones/aldeci.io",
                   tags={"env": "production"}, risk_score=4.2, org_id=org_id,
                   created_at=_days_ago(500), last_seen=_now()),
        # Extra VM
        CloudAsset(provider="azure", asset_type=CloudAssetType.VM, name="az-prod-jumpbox",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/az-prod-jumpbox",
                   tags={"env": "production", "role": "jumpbox"}, public_ip="20.40.50.1",
                   private_ip="10.0.10.99", risk_score=8.5, org_id=org_id,
                   created_at=_days_ago(7), last_seen=_now()),
        # Unmanaged (not in CMDB) - extra storage
        CloudAsset(provider="azure", asset_type=CloudAssetType.STORAGE, name="blob-shadow-it",
                   region="eastus", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/shadow-rg/providers/Microsoft.Storage/storageAccounts/shadowstorage",
                   tags={}, risk_score=9.5, org_id=org_id,
                   created_at=_days_ago(10), last_seen=_now()),
        # Extra serverless
        CloudAsset(provider="azure", asset_type=CloudAssetType.SERVERLESS, name="func-data-export",
                   region="westeurope", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/eu-rg/providers/Microsoft.Web/sites/func-data-export",
                   tags={"env": "production"}, risk_score=3.2, org_id=org_id,
                   created_at=_days_ago(25), last_seen=_now()),
        # Extra VM
        CloudAsset(provider="azure", asset_type=CloudAssetType.VM, name="az-staging-vm-001",
                   region="westeurope", account_id=subscription, resource_id="/subscriptions/sub-azure-0001-prod/resourceGroups/staging-rg/providers/Microsoft.Compute/virtualMachines/az-staging-vm-001",
                   tags={"env": "staging"}, public_ip=None,
                   private_ip="10.3.10.10", risk_score=1.5, org_id=org_id,
                   created_at=_days_ago(15), last_seen=_now()),
    ]
    return assets


def _build_gcp_assets(org_id: str) -> List[CloudAsset]:
    project = "aldeci-prod-gcp-001"
    assets = [
        # VMs (GCE)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.VM, name="gce-prod-api-001",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/zones/us-central1-a/instances/gce-prod-api-001",
                   tags={"env": "production", "team": "backend"}, public_ip="34.68.10.1",
                   private_ip="10.10.1.10", risk_score=5.8, org_id=org_id,
                   created_at=_days_ago(90), last_seen=_now()),
        CloudAsset(provider="gcp", asset_type=CloudAssetType.VM, name="gce-prod-api-002",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/zones/us-central1-b/instances/gce-prod-api-002",
                   tags={"env": "production", "team": "backend"}, public_ip=None,
                   private_ip="10.10.1.11", risk_score=4.5, org_id=org_id,
                   created_at=_days_ago(85), last_seen=_now()),
        CloudAsset(provider="gcp", asset_type=CloudAssetType.VM, name="gce-europe-analytics",
                   region="europe-west1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/zones/europe-west1-b/instances/gce-europe-analytics",
                   tags={"env": "production", "region": "eu"}, public_ip=None,
                   private_ip="10.20.1.10", risk_score=4.0, org_id=org_id,
                   created_at=_days_ago(50), last_seen=_now()),
        # Containers (GKE)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.CONTAINER, name="gke-prod-cluster",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/locations/us-central1/clusters/prod-cluster",
                   tags={"env": "production", "k8s": "1.28"}, risk_score=5.0, org_id=org_id,
                   created_at=_days_ago(70), last_seen=_now()),
        CloudAsset(provider="gcp", asset_type=CloudAssetType.CONTAINER, name="gcr-prod-registry",
                   region="us", account_id=project, resource_id="projects/aldeci-prod-gcp-001/gcr.io/aldeciprod",
                   tags={"env": "production"}, risk_score=3.8, org_id=org_id,
                   created_at=_days_ago(70), last_seen=_now()),
        # Serverless (Cloud Functions / Cloud Run)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.SERVERLESS, name="cf-intake-processor",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/locations/us-central1/functions/intake-processor",
                   tags={"env": "production", "runtime": "python311"}, risk_score=2.6, org_id=org_id,
                   created_at=_days_ago(40), last_seen=_now()),
        CloudAsset(provider="gcp", asset_type=CloudAssetType.SERVERLESS, name="cloudrun-api-v2",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/locations/us-central1/services/api-v2",
                   tags={"env": "production"}, public_ip="34.68.200.1",
                   risk_score=4.5, org_id=org_id, created_at=_days_ago(20), last_seen=_now()),
        # Databases (Cloud SQL / Firestore)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.DATABASE, name="cloudsql-prod-postgres",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/instances/prod-postgres",
                   tags={"env": "production", "engine": "postgres14"}, private_ip="10.10.5.10",
                   risk_score=8.2, org_id=org_id, created_at=_days_ago(180), last_seen=_now()),
        CloudAsset(provider="gcp", asset_type=CloudAssetType.DATABASE, name="firestore-prod-events",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/databases/(default)",
                   tags={"env": "production", "engine": "firestore"}, risk_score=5.0, org_id=org_id,
                   created_at=_days_ago(100), last_seen=_now()),
        CloudAsset(provider="gcp", asset_type=CloudAssetType.DATABASE, name="bigquery-analytics",
                   region="us", account_id=project, resource_id="projects/aldeci-prod-gcp-001/datasets/analytics",
                   tags={"env": "production", "engine": "bigquery"}, risk_score=6.0, org_id=org_id,
                   created_at=_days_ago(200), last_seen=_now()),
        # Storage (GCS)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.STORAGE, name="gcs-prod-assets",
                   region="us", account_id=project, resource_id="projects/aldeci-prod-gcp-001/buckets/aldeci-prod-assets",
                   tags={"env": "production"}, risk_score=5.0, org_id=org_id,
                   created_at=_days_ago(365), last_seen=_now()),
        CloudAsset(provider="gcp", asset_type=CloudAssetType.STORAGE, name="gcs-prod-backups",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/buckets/aldeci-prod-backups",
                   tags={"env": "production", "encrypted": "true"}, risk_score=2.8, org_id=org_id,
                   created_at=_days_ago(300), last_seen=_now()),
        # Network (Cloud Load Balancing / VPC)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.NETWORK, name="lb-prod-external",
                   region="global", account_id=project, resource_id="projects/aldeci-prod-gcp-001/global/forwardingRules/prod-external-lb",
                   tags={"env": "production"}, public_ip="34.107.100.1",
                   risk_score=5.5, org_id=org_id, created_at=_days_ago(180), last_seen=_now()),
        # IAM (Service Account)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.IAM, name="sa-prod-gke",
                   region="global", account_id=project, resource_id="projects/aldeci-prod-gcp-001/serviceAccounts/prod-gke@aldeci-prod-gcp-001.iam.gserviceaccount.com",
                   tags={"env": "production"}, risk_score=7.2, org_id=org_id,
                   created_at=_days_ago(365), last_seen=_now()),
        # Queue (Pub/Sub)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.QUEUE, name="pubsub-findings",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/topics/findings",
                   tags={"env": "production"}, risk_score=2.2, org_id=org_id,
                   created_at=_days_ago(90), last_seen=_now()),
        # Cache (Memorystore)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.CACHE, name="memorystore-prod-redis",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/locations/us-central1/instances/prod-redis",
                   tags={"env": "production"}, private_ip="10.10.6.10",
                   risk_score=3.5, org_id=org_id, created_at=_days_ago(120), last_seen=_now()),
        # API Gateway (Cloud Endpoints / Apigee)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.API_GATEWAY, name="apigee-prod",
                   region="us-central1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/locations/us-central1/apis/prod-api",
                   tags={"env": "production"}, public_ip="34.68.150.1",
                   risk_score=5.8, org_id=org_id, created_at=_days_ago(200), last_seen=_now()),
        # CDN (Cloud CDN)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.CDN, name="cdn-prod",
                   region="global", account_id=project, resource_id="projects/aldeci-prod-gcp-001/global/backendServices/cdn-prod",
                   tags={"env": "production"}, public_ip="34.100.10.1",
                   risk_score=3.2, org_id=org_id, created_at=_days_ago(365), last_seen=_now()),
        # DNS (Cloud DNS)
        CloudAsset(provider="gcp", asset_type=CloudAssetType.DNS, name="dns-aldeci-io",
                   region="global", account_id=project, resource_id="projects/aldeci-prod-gcp-001/managedZones/aldeci-io",
                   tags={"env": "production"}, risk_score=4.0, org_id=org_id,
                   created_at=_days_ago(500), last_seen=_now()),
        # Unmanaged shadow IT resource
        CloudAsset(provider="gcp", asset_type=CloudAssetType.VM, name="gce-shadow-mining",
                   region="asia-east1", account_id=project, resource_id="projects/aldeci-prod-gcp-001/zones/asia-east1-a/instances/gce-shadow-mining",
                   tags={}, public_ip="35.220.10.1",
                   private_ip="10.30.1.10", risk_score=9.8, org_id=org_id,
                   created_at=_days_ago(3), last_seen=_now()),
    ]
    return assets


# ---------------------------------------------------------------------------
# Main CloudDiscovery class
# ---------------------------------------------------------------------------


class CloudDiscovery:
    """Multi-cloud asset discovery and inventory management."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _CloudDiscoveryDB(db_path)

    # ------------------------------------------------------------------
    # Discovery methods
    # ------------------------------------------------------------------

    def discover_aws(self, org_id: str) -> List[CloudAsset]:
        """Enumerate AWS resources. Uses mock data when no credentials available."""
        logger.info("cloud_discovery.discover_aws", org_id=org_id)
        try:
            assets = self._live_discover_aws(org_id)
        except Exception:
            logger.info("cloud_discovery.discover_aws.mock_fallback", org_id=org_id)
            assets = _build_aws_assets(org_id)

        self._db.upsert_many(assets)
        logger.info("cloud_discovery.discover_aws.complete", org_id=org_id, count=len(assets))
        return assets

    def discover_azure(self, org_id: str) -> List[CloudAsset]:
        """Enumerate Azure resources. Uses mock data when no credentials available."""
        logger.info("cloud_discovery.discover_azure", org_id=org_id)
        try:
            assets = self._live_discover_azure(org_id)
        except Exception:
            logger.info("cloud_discovery.discover_azure.mock_fallback", org_id=org_id)
            assets = _build_azure_assets(org_id)

        self._db.upsert_many(assets)
        logger.info("cloud_discovery.discover_azure.complete", org_id=org_id, count=len(assets))
        return assets

    def discover_gcp(self, org_id: str) -> List[CloudAsset]:
        """Enumerate GCP resources. Uses mock data when no credentials available."""
        logger.info("cloud_discovery.discover_gcp", org_id=org_id)
        try:
            assets = self._live_discover_gcp(org_id)
        except Exception:
            logger.info("cloud_discovery.discover_gcp.mock_fallback", org_id=org_id)
            assets = _build_gcp_assets(org_id)

        self._db.upsert_many(assets)
        logger.info("cloud_discovery.discover_gcp.complete", org_id=org_id, count=len(assets))
        return assets

    def discover_all(self, org_id: str) -> List[CloudAsset]:
        """Discover assets across all three cloud providers."""
        logger.info("cloud_discovery.discover_all", org_id=org_id)
        aws = self.discover_aws(org_id)
        azure = self.discover_azure(org_id)
        gcp = self.discover_gcp(org_id)
        all_assets = aws + azure + gcp
        logger.info("cloud_discovery.discover_all.complete", org_id=org_id, total=len(all_assets))
        return all_assets

    # ------------------------------------------------------------------
    # Inventory queries
    # ------------------------------------------------------------------

    def get_asset_inventory(
        self,
        org_id: str,
        provider: Optional[str] = None,
        asset_type: Optional[str] = None,
        region: Optional[str] = None,
        account_id: Optional[str] = None,
    ) -> List[CloudAsset]:
        """Full inventory with optional filters."""
        return self._db.list_assets(
            org_id=org_id,
            provider=provider,
            asset_type=asset_type,
            region=region,
            account_id=account_id,
        )

    def get_unmanaged_assets(self, org_id: str) -> List[CloudAsset]:
        """Assets not present in CMDB (shadow IT / unmanaged resources)."""
        all_assets = self._db.list_assets(org_id=org_id)
        cmdb_ids = self._db.get_cmdb_resource_ids(org_id)
        return [a for a in all_assets if a.resource_id not in cmdb_ids]

    def get_public_assets(self, org_id: str) -> List[CloudAsset]:
        """Internet-exposed assets (have a public IP)."""
        return self._db.list_public_assets(org_id=org_id)

    def get_asset_drift(self, org_id: str, days: int = 7) -> Dict[str, Any]:
        """New and removed assets within the lookback window."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        new_assets = self._db.list_new_assets_since(org_id=org_id, since=cutoff)
        removed_assets = self._db.list_removed_assets_since(org_id=org_id, since=cutoff)
        return {
            "lookback_days": days,
            "new_count": len(new_assets),
            "removed_count": len(removed_assets),
            "new_assets": [a.model_dump() for a in new_assets],
            "removed_assets": [a.model_dump() for a in removed_assets],
        }

    def get_discovery_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregated stats by provider, type, and region."""
        return self._db.get_stats(org_id=org_id)

    def register_cmdb_asset(self, resource_id: str, org_id: str) -> None:
        """Mark a resource as known/managed in the CMDB."""
        self._db.register_cmdb_asset(resource_id=resource_id, org_id=org_id)

    # ------------------------------------------------------------------
    # Live discovery stubs (raise to trigger mock fallback)
    # ------------------------------------------------------------------

    def _live_discover_aws(self, org_id: str) -> List[CloudAsset]:
        """Attempt live AWS discovery via boto3. Raises if unavailable."""
        import boto3  # type: ignore[import-untyped]
        assets: List[CloudAsset] = []
        ec2 = boto3.client("ec2")
        response = ec2.describe_instances()
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]
                name = next(
                    (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                    instance_id,
                )
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                assets.append(CloudAsset(
                    provider="aws",
                    asset_type=CloudAssetType.VM,
                    name=name,
                    region=ec2.meta.region_name,
                    account_id=instance.get("OwnerId", "unknown"),
                    resource_id=instance_id,
                    tags=tags,
                    public_ip=instance.get("PublicIpAddress"),
                    private_ip=instance.get("PrivateIpAddress"),
                    org_id=org_id,
                ))
        return assets

    def _live_discover_azure(self, org_id: str) -> List[CloudAsset]:
        """Attempt live Azure discovery via azure-mgmt-compute. Raises if unavailable."""
        import os as _os

        from azure.identity import (
            DefaultAzureCredential,  # type: ignore[import-untyped]
        )
        from azure.mgmt.compute import (
            ComputeManagementClient,  # type: ignore[import-untyped]
        )
        credential = DefaultAzureCredential()
        subscription_id = _os.environ["AZURE_SUBSCRIPTION_ID"]
        client = ComputeManagementClient(credential, subscription_id)
        assets: List[CloudAsset] = []
        for vm in client.virtual_machines.list_all():
            assets.append(CloudAsset(
                provider="azure",
                asset_type=CloudAssetType.VM,
                name=vm.name,
                region=vm.location,
                account_id=subscription_id,
                resource_id=vm.id,
                tags=dict(vm.tags or {}),
                org_id=org_id,
            ))
        return assets

    def _live_discover_gcp(self, org_id: str) -> List[CloudAsset]:
        """Attempt live GCP discovery via google-cloud-compute. Raises if unavailable."""
        import os as _os

        from google.cloud import compute_v1  # type: ignore[import-untyped]
        project = _os.environ["GCP_PROJECT_ID"]
        client = compute_v1.InstancesClient()
        assets: List[CloudAsset] = []
        for zone_instances in client.aggregated_list(project=project):
            zone_name, instance_list = zone_instances
            for instance in getattr(instance_list, "instances", []):
                region = "-".join(zone_name.replace("zones/", "").split("-")[:-1])
                assets.append(CloudAsset(
                    provider="gcp",
                    asset_type=CloudAssetType.VM,
                    name=instance.name,
                    region=region,
                    account_id=project,
                    resource_id=f"projects/{project}/zones/{zone_name.replace('zones/', '')}/instances/{instance.name}",
                    tags=dict(instance.labels or {}),
                    org_id=org_id,
                ))
        return assets


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_instance: Optional[CloudDiscovery] = None
_instance_lock = threading.Lock()


def get_cloud_discovery(db_path: str = _DEFAULT_DB) -> CloudDiscovery:
    """Return the process-wide CloudDiscovery singleton."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = CloudDiscovery(db_path=db_path)
    return _instance
