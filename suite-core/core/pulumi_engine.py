"""
Pulumi Cloud Engine — ALDECI.

Wraps the Pulumi Cloud REST API (https://api.pulumi.com) and provides a
process-wide singleton. NO SQLite cache — Pulumi responses include
deployment state that is short-lived; we forward live to upstream every
call.

Supported endpoints
-------------------
* GET  /api/user                                                        — viewer + orgs
* GET  /api/orgs/{org}/stacks                                           — stacks list
* GET  /api/stacks/{org}/{project}/{stack}                              — stack detail
* GET  /api/stacks/{org}/{project}/{stack}/updates                      — updates list
* GET  /api/stacks/{org}/{project}/{stack}/updates/{version}            — single update
* GET  /api/stacks/{org}/{project}/{stack}/updates/latest               — latest update
* GET  /api/stacks/{org}/{project}/{stack}/exports                      — state export
* GET  /api/orgs/{org}/policygroups                                     — policy groups
* GET  /api/orgs/{org}/policygroups/{group_name}                        — single group
* GET  /api/orgs/{org}/policypacks                                      — policy packs
* GET  /api/orgs/{org}/policypacks/{pack_name}/versions/{version}/policies — policies

Auth
----
``Authorization: token {PULUMI_ACCESS_TOKEN}``
Note: the prefix is literally ``token``, not ``Bearer``.

Self-hosted overrides
---------------------
* ``PULUMI_BACKEND_URL`` — overrides the API base for self-hosted Pulumi
  Cloud-compatible deployments.

NO MOCKS rule
-------------
* PULUMI_ACCESS_TOKEN unset:
    - All live endpoints raise PulumiUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Pulumi.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_PULUMI_API_BASE = "https://api.pulumi.com"
DEFAULT_TIMEOUT_SECONDS = 12.0


class PulumiUnavailableError(RuntimeError):
    """Raised when PULUMI_ACCESS_TOKEN is missing, network failed, or
    upstream returned an unrecoverable status."""


class PulumiEngine:
    """Thread-safe Pulumi Cloud REST client (no cache)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        base_url: Optional[str] = None,
    ) -> None:
        self._explicit_api_key = api_key
        self._explicit_base_url = base_url
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("PULUMI_ACCESS_TOKEN")
        return v or None

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def _base_url(self) -> str:
        if self._explicit_base_url:
            return self._explicit_base_url.rstrip("/")
        v = os.environ.get("PULUMI_BACKEND_URL")
        if v:
            return v.rstrip("/")
        return DEFAULT_PULUMI_API_BASE

    def _headers(self) -> Dict[str, str]:
        api_key = self._api_key()
        if not api_key:
            raise PulumiUnavailableError(
                "PULUMI_ACCESS_TOKEN is not configured"
            )
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"token {api_key}",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        headers = self._headers()
        url = f"{self._base_url()}{path}"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            else:
                raise PulumiUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise PulumiUnavailableError(
                f"Pulumi request failed: {exc}"
            ) from exc
        if resp.status_code in (401, 403):
            raise PulumiUnavailableError(
                f"Pulumi rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise PulumiUnavailableError(
                f"Pulumi resource not found: {path}"
            )
        if resp.status_code == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"Pulumi validation error: {body}")
        if resp.status_code == 429:
            raise PulumiUnavailableError(
                "Pulumi rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise PulumiUnavailableError(
                f"Pulumi returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise PulumiUnavailableError(
                f"Pulumi returned non-JSON response: {exc}"
            ) from exc
        return data if isinstance(data, dict) else {"data": data}

    # ----------------------------------------------------------- API calls

    def get_user(self) -> Dict[str, Any]:
        """GET /api/user — viewer profile + orgs."""
        raw = self._request("GET", "/api/user")
        return self._normalize_user(raw)

    def list_stacks(
        self,
        org: str,
        *,
        continuation_token: Optional[str] = None,
        project: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /api/orgs/{org}/stacks — list stacks (paginated)."""
        if not org:
            raise ValueError("org must not be empty")
        params: Dict[str, Any] = {}
        if continuation_token:
            params["continuationToken"] = continuation_token
        if project:
            params["project"] = project
        if tag:
            params["tag"] = tag
        raw = self._request(
            "GET",
            f"/api/orgs/{org}/stacks",
            params=params or None,
        )
        return self._normalize_stacks_list(raw)

    def get_stack(self, org: str, project: str, stack: str) -> Dict[str, Any]:
        """GET /api/stacks/{org}/{project}/{stack} — stack detail."""
        if not org:
            raise ValueError("org must not be empty")
        if not project:
            raise ValueError("project must not be empty")
        if not stack:
            raise ValueError("stack must not be empty")
        raw = self._request(
            "GET",
            f"/api/stacks/{org}/{project}/{stack}",
        )
        return self._normalize_stack(raw)

    def list_updates(
        self,
        org: str,
        project: str,
        stack: str,
        *,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
    ) -> Dict[str, Any]:
        """GET /api/stacks/{org}/{project}/{stack}/updates."""
        if not org or not project or not stack:
            raise ValueError("org/project/stack must not be empty")
        params: Dict[str, Any] = {}
        if page is not None:
            params["page"] = int(page)
        if page_size is not None:
            params["pageSize"] = int(page_size)
        raw = self._request(
            "GET",
            f"/api/stacks/{org}/{project}/{stack}/updates",
            params=params or None,
        )
        return self._normalize_updates_list(raw)

    def get_update(
        self, org: str, project: str, stack: str, version: str
    ) -> Dict[str, Any]:
        """GET /api/stacks/{org}/{project}/{stack}/updates/{version}."""
        if not org or not project or not stack:
            raise ValueError("org/project/stack must not be empty")
        if not version:
            raise ValueError("version must not be empty")
        raw = self._request(
            "GET",
            f"/api/stacks/{org}/{project}/{stack}/updates/{version}",
        )
        return self._normalize_update_entry(raw)

    def get_latest_update(
        self, org: str, project: str, stack: str
    ) -> Dict[str, Any]:
        """GET /api/stacks/{org}/{project}/{stack}/updates/latest."""
        if not org or not project or not stack:
            raise ValueError("org/project/stack must not be empty")
        raw = self._request(
            "GET",
            f"/api/stacks/{org}/{project}/{stack}/updates/latest",
        )
        return self._normalize_update_entry(raw)

    def get_exports(
        self, org: str, project: str, stack: str
    ) -> Dict[str, Any]:
        """GET /api/stacks/{org}/{project}/{stack}/exports — state export."""
        if not org or not project or not stack:
            raise ValueError("org/project/stack must not be empty")
        raw = self._request(
            "GET",
            f"/api/stacks/{org}/{project}/{stack}/exports",
        )
        return self._normalize_export(raw)

    def list_policy_groups(
        self, org: str, *, continuation_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """GET /api/orgs/{org}/policygroups — list policy groups."""
        if not org:
            raise ValueError("org must not be empty")
        params: Dict[str, Any] = {}
        if continuation_token:
            params["continuationToken"] = continuation_token
        raw = self._request(
            "GET",
            f"/api/orgs/{org}/policygroups",
            params=params or None,
        )
        return self._normalize_policy_groups(raw)

    def get_policy_group(self, org: str, group_name: str) -> Dict[str, Any]:
        """GET /api/orgs/{org}/policygroups/{group_name}."""
        if not org:
            raise ValueError("org must not be empty")
        if not group_name:
            raise ValueError("group_name must not be empty")
        raw = self._request(
            "GET",
            f"/api/orgs/{org}/policygroups/{group_name}",
        )
        return self._normalize_policy_group_entry(raw)

    def list_policy_packs(
        self, org: str, *, continuation_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """GET /api/orgs/{org}/policypacks — required + optional policy packs."""
        if not org:
            raise ValueError("org must not be empty")
        params: Dict[str, Any] = {}
        if continuation_token:
            params["continuationToken"] = continuation_token
        raw = self._request(
            "GET",
            f"/api/orgs/{org}/policypacks",
            params=params or None,
        )
        return self._normalize_policy_packs(raw)

    def get_policy_pack_policies(
        self, org: str, pack_name: str, version: str
    ) -> Dict[str, Any]:
        """GET /api/orgs/{org}/policypacks/{pack_name}/versions/{version}/policies."""
        if not org or not pack_name or not version:
            raise ValueError("org/pack_name/version must not be empty")
        raw = self._request(
            "GET",
            f"/api/orgs/{org}/policypacks/{pack_name}/versions/{version}/policies",
        )
        # Pulumi returns a flexible shape — pass through with safe key normalisation.
        if not isinstance(raw, dict):
            raw = {}
        return raw

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_user(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        orgs_in = (
            raw.get("organizations")
            if isinstance(raw.get("organizations"), list)
            else []
        )
        orgs_out: List[Dict[str, Any]] = []
        for org in orgs_in:
            if not isinstance(org, dict):
                continue
            orgs_out.append(
                {
                    "githubLogin": org.get("githubLogin") or "",
                    "name": org.get("name") or "",
                    "avatarUrl": org.get("avatarUrl") or "",
                }
            )
        return {
            "name": raw.get("name") or "",
            "githubLogin": raw.get("githubLogin") or "",
            "email": raw.get("email") or "",
            "avatarUrl": raw.get("avatarUrl") or "",
            "organizations": orgs_out,
        }

    @staticmethod
    def _normalize_stacks_list(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        stacks_in = raw.get("stacks") if isinstance(raw.get("stacks"), list) else []
        stacks_out: List[Dict[str, Any]] = []
        for s in stacks_in:
            if not isinstance(s, dict):
                continue
            stacks_out.append(
                {
                    "orgName": s.get("orgName") or "",
                    "projectName": s.get("projectName") or "",
                    "stackName": s.get("stackName") or "",
                    "lastUpdate": int(s.get("lastUpdate") or 0),
                    "resourceCount": int(s.get("resourceCount") or 0),
                }
            )
        return {
            "stacks": stacks_out,
            "continuationToken": raw.get("continuationToken") or "",
        }

    @staticmethod
    def _normalize_stack(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        tags = raw.get("tags") if isinstance(raw.get("tags"), dict) else {}
        links = raw.get("links") if isinstance(raw.get("links"), dict) else {}
        config = raw.get("config") if isinstance(raw.get("config"), dict) else {}
        settings_in = (
            raw.get("settings") if isinstance(raw.get("settings"), dict) else {}
        )
        settings_out: Dict[str, Any] = {}
        if isinstance(settings_in.get("secretsProvider"), dict) or isinstance(
            settings_in.get("secretsProvider"), str
        ):
            settings_out["secretsProvider"] = settings_in.get("secretsProvider")
        else:
            settings_out["secretsProvider"] = ""
        envs_in = (
            raw.get("environments")
            if isinstance(raw.get("environments"), list)
            else []
        )
        envs_out: List[Any] = [e for e in envs_in if isinstance(e, (str, dict))]
        return {
            "orgName": raw.get("orgName") or "",
            "projectName": raw.get("projectName") or "",
            "stackName": raw.get("stackName") or "",
            "currentOperation": raw.get("currentOperation") or "",
            "lastUpdate": int(raw.get("lastUpdate") or 0),
            "resourceCount": int(raw.get("resourceCount") or 0),
            "version": int(raw.get("version") or 0),
            "tags": tags,
            "links": links,
            "config": config,
            "settings": settings_out,
            "runtime": raw.get("runtime") or "",
            "environments": envs_out,
        }

    @staticmethod
    def _normalize_update_entry(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        info_in = raw.get("info") if isinstance(raw.get("info"), dict) else raw
        env = raw.get("environment") if isinstance(raw.get("environment"), dict) else {}
        deploy = raw.get("deployment") if isinstance(raw.get("deployment"), dict) else {}
        info_env = (
            info_in.get("environment")
            if isinstance(info_in.get("environment"), dict)
            else {}
        )
        rc = (
            info_in.get("resourceChanges")
            if isinstance(info_in.get("resourceChanges"), dict)
            else {}
        )
        info_deploy = (
            info_in.get("deployment")
            if isinstance(info_in.get("deployment"), dict)
            else {}
        )
        ops = (
            info_deploy.get("operations")
            if isinstance(info_deploy.get("operations"), list)
            else []
        )
        info_out = {
            "version": int(info_in.get("version") or 0),
            "kind": info_in.get("kind") or "",
            "startTime": int(info_in.get("startTime") or 0),
            "endTime": int(info_in.get("endTime") or 0),
            "message": info_in.get("message") or "",
            "environment": info_env,
            "resourceChanges": {
                "create": int(rc.get("create") or 0),
                "update": int(rc.get("update") or 0),
                "delete": int(rc.get("delete") or 0),
                "replace": int(rc.get("replace") or 0),
                "same": int(rc.get("same") or 0),
            },
            "resourceCount": int(info_in.get("resourceCount") or 0),
            "deployment": {"operations": ops if isinstance(ops, list) else []},
        }
        return {
            "info": info_out,
            "environment": env,
            "deployment": deploy,
        }

    @classmethod
    def _normalize_updates_list(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        ups_in = (
            raw.get("updates") if isinstance(raw.get("updates"), list) else []
        )
        ups_out: List[Dict[str, Any]] = []
        for u in ups_in:
            if not isinstance(u, dict):
                continue
            ups_out.append(cls._normalize_update_entry(u))
        return {"updates": ups_out}

    @staticmethod
    def _normalize_export(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        deploy_in = raw.get("deployment") if isinstance(raw.get("deployment"), dict) else {}
        manifest = (
            deploy_in.get("manifest")
            if isinstance(deploy_in.get("manifest"), dict)
            else {}
        )
        sps = (
            deploy_in.get("secrets_providers")
            if isinstance(deploy_in.get("secrets_providers"), list)
            else []
        )
        resources_in = (
            deploy_in.get("resources")
            if isinstance(deploy_in.get("resources"), list)
            else []
        )
        resources_out: List[Dict[str, Any]] = []
        for r in resources_in:
            if not isinstance(r, dict):
                continue
            sp = r.get("sourcePosition") if isinstance(r.get("sourcePosition"), dict) else {}
            resources_out.append(
                {
                    "urn": r.get("urn") or "",
                    "custom": bool(r.get("custom", False)),
                    "id": r.get("id") or "",
                    "type": r.get("type") or "",
                    "inputs": r.get("inputs") if isinstance(r.get("inputs"), dict) else {},
                    "outputs": r.get("outputs") if isinstance(r.get("outputs"), dict) else {},
                    "parent": r.get("parent") or "",
                    "dependencies": list(r.get("dependencies") or []),
                    "propertyDependencies": (
                        r.get("propertyDependencies")
                        if isinstance(r.get("propertyDependencies"), dict)
                        else {}
                    ),
                    "provider": r.get("provider") or "",
                    "protect": bool(r.get("protect", False)),
                    "externalDependencies": list(r.get("externalDependencies") or []),
                    "additionalSecretOutputs": list(
                        r.get("additionalSecretOutputs") or []
                    ),
                    "aliases": list(r.get("aliases") or []),
                    "created": r.get("created") or "",
                    "modified": r.get("modified") or "",
                    "sourcePosition": {
                        "uri": sp.get("uri") or "",
                        "line": int(sp.get("line") or 0),
                        "column": int(sp.get("column") or 0),
                    },
                }
            )
        pending = (
            deploy_in.get("pendingOperations")
            if isinstance(deploy_in.get("pendingOperations"), list)
            else []
        )
        sps_root = deploy_in.get("secretsProviders")
        sps_root = sps_root if isinstance(sps_root, dict) else {}
        return {
            "version": int(raw.get("version") or 0),
            "deployment": {
                "manifest": manifest,
                "secrets_providers": sps,
                "resources": resources_out,
                "pendingOperations": pending,
                "secretsProviders": {
                    "type": sps_root.get("type") or "",
                    "state": sps_root.get("state") if isinstance(sps_root.get("state"), dict) else {},
                },
            },
        }

    @staticmethod
    def _normalize_policy_groups(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        groups_in = (
            raw.get("policyGroups")
            if isinstance(raw.get("policyGroups"), list)
            else []
        )
        groups_out: List[Dict[str, Any]] = []
        for g in groups_in:
            if not isinstance(g, dict):
                continue
            groups_out.append(
                {
                    "name": g.get("name") or "",
                    "description": g.get("description") or "",
                    "isOrgDefault": bool(g.get("isOrgDefault", False)),
                    "numStacks": int(g.get("numStacks") or 0),
                    "numEnabledPolicyPacks": int(
                        g.get("numEnabledPolicyPacks") or 0
                    ),
                }
            )
        return {"policyGroups": groups_out}

    @staticmethod
    def _normalize_policy_group_entry(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "name": raw.get("name") or "",
            "description": raw.get("description") or "",
            "isOrgDefault": bool(raw.get("isOrgDefault", False)),
            "numStacks": int(raw.get("numStacks") or 0),
            "numEnabledPolicyPacks": int(raw.get("numEnabledPolicyPacks") or 0),
            "stacks": raw.get("stacks") if isinstance(raw.get("stacks"), list) else [],
            "policyPacks": raw.get("policyPacks") if isinstance(raw.get("policyPacks"), list) else [],
        }

    @staticmethod
    def _normalize_policy_packs(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        required_in = (
            raw.get("requiredPolicies")
            if isinstance(raw.get("requiredPolicies"), list)
            else []
        )
        required_out: List[Dict[str, Any]] = []
        for p in required_in:
            if not isinstance(p, dict):
                continue
            required_out.append(
                {
                    "name": p.get("name") or "",
                    "displayName": p.get("displayName") or "",
                    "version": int(p.get("version") or 0),
                    "versionTag": p.get("versionTag") or "",
                    "latestVersion": int(p.get("latestVersion") or 0),
                    "latestVersionTag": p.get("latestVersionTag") or "",
                    "enforcementLevel": p.get("enforcementLevel") or "",
                }
            )
        packs_in = (
            raw.get("policyPacks")
            if isinstance(raw.get("policyPacks"), list)
            else []
        )
        packs_out: List[Dict[str, Any]] = []
        for p in packs_in:
            if not isinstance(p, dict):
                continue
            packs_out.append(
                {
                    "name": p.get("name") or "",
                    "displayName": p.get("displayName") or "",
                    "latestVersion": int(p.get("latestVersion") or 0),
                    "latestVersionTag": p.get("latestVersionTag") or "",
                }
            )
        return {
            "requiredPolicies": required_out,
            "policyPacks": packs_out,
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[PulumiEngine] = None
_singleton_lock = threading.Lock()


def get_pulumi_engine(
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    base_url: Optional[str] = None,
) -> PulumiEngine:
    """Return the process-wide PulumiEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = PulumiEngine(
                api_key=api_key, client=client, base_url=base_url
            )
        return _singleton


def reset_pulumi_engine() -> None:
    """Tear down the singleton — used by tests with stub clients."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "PulumiEngine",
    "PulumiUnavailableError",
    "DEFAULT_PULUMI_API_BASE",
    "get_pulumi_engine",
    "reset_pulumi_engine",
]
