#!/usr/bin/env python3
"""
ALDECI CSPM Kind Cluster Test
==============================
Scans a local kind cluster for CIS Kubernetes benchmark misconfigurations
and POSTs findings to ALDECI's /api/v1/kubernetes-security endpoints.

Usage:
    python scripts/cspm_kind_test.py [--dry-run] [--cluster KIND_CLUSTER_NAME]
                                     [--aldeci-url URL] [--org-id ORG]

    --dry-run        Show what would be done without touching the cluster or API.
    --cluster        kind cluster name (default: aldeci-lab)
    --aldeci-url     ALDECI base URL (default: http://localhost:8000)
    --org-id         Organisation ID to use (default: cspm-test)

Requires:
    - kind (https://kind.sigs.k8s.io)
    - kubectl (in PATH, kubeconfig auto-resolved from kind context)
    - Python 3.9+
    - Running ALDECI backend at --aldeci-url

What it does:
    1. Verifies kind + cluster exist (or creates them in non-dry-run mode)
    2. Deploys 4 intentionally insecure workloads for testing
    3. Runs CIS Kubernetes benchmark checks via kubectl
    4. Registers the cluster in ALDECI
    5. POSTs each finding to /api/v1/kubernetes-security/findings
    6. Triggers /api/v1/kubernetes-security/clusters/{id}/cis-benchmark
    7. Prints a summary report
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Config defaults
# ---------------------------------------------------------------------------

DEFAULT_CLUSTER   = "aldeci-lab"
DEFAULT_URL       = "http://localhost:8000"
DEFAULT_ORG       = "cspm-test"
API_TOKEN         = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"

KIND_CONFIG = """
apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
nodes:
  - role: control-plane
  - role: worker
  - role: worker
""".strip()

# ---------------------------------------------------------------------------
# Insecure workload manifests (intentionally misconfigured for CSPM testing)
# ---------------------------------------------------------------------------

INSECURE_WORKLOADS: List[Dict[str, Any]] = [
    # 1. Pod without resource limits — CIS 5.2.4
    {
        "name": "no-resource-limits",
        "description": "Pod with no CPU/memory limits (CIS 5.2.4)",
        "cis_control": "5.2.4",
        "severity": "high",
        "finding_type": "no_resource_limits",
        "manifest": {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "cspm-test-no-limits",
                "namespace": "default",
                "labels": {"app": "cspm-test", "test": "no-limits"},
            },
            "spec": {
                "containers": [
                    {
                        "name": "nginx",
                        "image": "nginx:alpine",
                        # No resources.limits deliberately
                    }
                ]
            },
        },
    },
    # 2. Container running as root — CIS 5.2.6
    {
        "name": "container-as-root",
        "description": "Container with no runAsNonRoot constraint (CIS 5.2.6)",
        "cis_control": "5.2.6",
        "severity": "critical",
        "finding_type": "privileged_container",
        "manifest": {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "cspm-test-root-container",
                "namespace": "default",
                "labels": {"app": "cspm-test", "test": "root-container"},
            },
            "spec": {
                "containers": [
                    {
                        "name": "busybox",
                        "image": "busybox:latest",
                        "command": ["sleep", "3600"],
                        "securityContext": {
                            "runAsUser": 0,     # root
                            "runAsNonRoot": False,
                            "allowPrivilegeEscalation": True,
                        },
                    }
                ]
            },
        },
    },
    # 3. Service with no network policy — CIS 5.3.2
    {
        "name": "no-network-policy",
        "description": "Service exposed with no NetworkPolicy restricting ingress (CIS 5.3.2)",
        "cis_control": "5.3.2",
        "severity": "medium",
        "finding_type": "missing_network_policy",
        "manifest": {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "cspm-test-open-service",
                "namespace": "default",
                "labels": {"app": "cspm-test", "test": "no-netpol"},
            },
            "spec": {
                "selector": {"app": "cspm-test"},
                "ports": [{"port": 80, "targetPort": 80}],
                "type": "ClusterIP",
            },
        },
    },
    # 4. Secret stored as plaintext env var — CIS 5.4.1
    {
        "name": "plaintext-secret",
        "description": "Sensitive value passed as plaintext env var instead of Secret (CIS 5.4.1)",
        "cis_control": "5.4.1",
        "severity": "high",
        "finding_type": "secret_in_env",
        "manifest": {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "cspm-test-plaintext-secret",
                "namespace": "default",
                "labels": {"app": "cspm-test", "test": "plaintext-secret"},
            },
            "spec": {
                "containers": [
                    {
                        "name": "alpine",
                        "image": "alpine:latest",
                        "command": ["sleep", "3600"],
                        "env": [
                            {
                                "name": "DATABASE_PASSWORD",
                                "value": "super_secret_plaintext_pw_123!",  # plaintext!
                            },
                            {
                                "name": "API_KEY",
                                "value": "sk-hardcoded-api-key-do-not-do-this",
                            },
                        ],
                    }
                ]
            },
        },
    },
]

# ---------------------------------------------------------------------------
# CIS Kubernetes Benchmark checks (kubectl-based, no kube-bench required)
# ---------------------------------------------------------------------------

@dataclass
class CISCheck:
    cis_id: str
    title: str
    severity: str
    finding_type: str
    remediation: str
    kubectl_check: str  # shell command that returns JSON/text to analyze
    detect_fn: str      # name of detection logic method

CIS_CHECKS: List[CISCheck] = [
    CISCheck(
        cis_id="5.2.4",
        title="Minimize the admission of containers wishing to share the host network namespace",
        severity="high",
        finding_type="no_resource_limits",
        remediation="Set resources.requests and resources.limits for all containers.",
        kubectl_check=(
            "kubectl get pods --all-namespaces -o json "
            "--context kind-{cluster}"
        ),
        detect_fn="detect_no_resource_limits",
    ),
    CISCheck(
        cis_id="5.2.6",
        title="Minimize the admission of root containers",
        severity="critical",
        finding_type="privileged_container",
        remediation=(
            "Set securityContext.runAsNonRoot=true and securityContext.runAsUser to a non-zero UID."
        ),
        kubectl_check=(
            "kubectl get pods --all-namespaces -o json "
            "--context kind-{cluster}"
        ),
        detect_fn="detect_root_containers",
    ),
    CISCheck(
        cis_id="5.3.2",
        title="Ensure that all Namespaces have Network Policies defined",
        severity="medium",
        finding_type="missing_network_policy",
        remediation=(
            "Create NetworkPolicy objects for every namespace to restrict pod-to-pod communication."
        ),
        kubectl_check=(
            "kubectl get namespaces -o json --context kind-{cluster}"
        ),
        detect_fn="detect_missing_network_policies",
    ),
    CISCheck(
        cis_id="5.4.1",
        title="Prefer using secrets as files over secrets as environment variables",
        severity="high",
        finding_type="secret_in_env",
        remediation=(
            "Mount secrets as volumes or use secretKeyRef. "
            "Never pass sensitive values as literal env var values."
        ),
        kubectl_check=(
            "kubectl get pods --all-namespaces -o json "
            "--context kind-{cluster}"
        ),
        detect_fn="detect_plaintext_secrets",
    ),
    CISCheck(
        cis_id="5.2.1",
        title="Ensure that the cluster-admin role is only used where required",
        severity="critical",
        finding_type="excessive_rbac_permissions",
        remediation=(
            "Audit ClusterRoleBindings that reference cluster-admin. "
            "Replace with narrowly scoped roles."
        ),
        kubectl_check=(
            "kubectl get clusterrolebindings -o json --context kind-{cluster}"
        ),
        detect_fn="detect_cluster_admin_bindings",
    ),
    CISCheck(
        cis_id="1.2.1",
        title="Ensure that anonymous requests to the API server are authorized",
        severity="critical",
        finding_type="api_server_anonymous_auth",
        remediation=(
            "Set --anonymous-auth=false in the API server configuration."
        ),
        kubectl_check=(
            "kubectl get pods -n kube-system -o json --context kind-{cluster}"
        ),
        detect_fn="detect_anonymous_auth",
    ),
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("cspm-kind-test")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: str, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def _kubectl_json(cmd: str) -> Optional[Dict[str, Any]]:
    """Run a kubectl command that outputs JSON and return parsed dict."""
    try:
        result = _run(cmd, check=False)
        if result.returncode != 0:
            log.warning("kubectl failed: %s", result.stderr.strip())
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as exc:
        log.warning("kubectl_json error: %s", exc)
        return None


def _api(
    method: str,
    path: str,
    base_url: str,
    body: Optional[Dict] = None,
    dry_run: bool = False,
    _retries: int = 4,
) -> Optional[Dict[str, Any]]:
    """Make an authenticated request to the ALDECI API with exponential-backoff retry."""
    url = f"{base_url}{path}"
    if dry_run:
        log.info("[DRY-RUN] %s %s  body=%s", method, url, json.dumps(body) if body else "none")
        return {"dry_run": True, "id": str(uuid.uuid4()), "status": "simulated"}

    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "X-API-Key": API_TOKEN,
            "Content-Type": "application/json",
        },
        method=method,
    )
    for attempt in range(_retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode(errors="replace")
            if exc.code == 429 and attempt < _retries - 1:
                wait = 2 ** attempt  # 1, 2, 4 seconds
                log.warning(
                    "HTTP 429 on %s %s — retrying in %ds (attempt %d/%d)",
                    method, url, wait, attempt + 1, _retries,
                )
                time.sleep(wait)
                continue
            log.error("API %s %s -> HTTP %s: %s", method, url, exc.code, body_text[:200])
            return None
        except Exception as exc:
            log.error("API error %s %s: %s", method, url, exc)
            return None
    return None


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------


def detect_no_resource_limits(pods_json: Dict, cluster: str) -> List[Dict]:
    findings = []
    for item in pods_json.get("items", []):
        ns = item["metadata"]["namespace"]
        name = item["metadata"]["name"]
        if ns.startswith("kube-") or name.startswith("cspm-test-"):
            # skip system pods; cspm-test pods are our intentional ones — still report
            pass
        for c in item["spec"].get("containers", []):
            resources = c.get("resources", {})
            if not resources.get("limits"):
                findings.append({
                    "namespace": ns,
                    "resource_name": name,
                    "resource_type": "Pod",
                    "description": (
                        f"Container '{c['name']}' in pod '{name}' (ns: {ns}) "
                        "has no resource limits set."
                    ),
                })
    return findings


_SYSTEM_NAMESPACES = frozenset(
    {"kube-system", "kube-public", "kube-node-lease"}
)


def detect_root_containers(pods_json: Dict, cluster: str) -> List[Dict]:
    findings = []
    for item in pods_json.get("items", []):
        ns = item["metadata"]["namespace"]
        name = item["metadata"]["name"]
        # Skip system namespaces — kube-system components legitimately run as root
        if ns in _SYSTEM_NAMESPACES:
            continue
        pod_sc = item["spec"].get("securityContext", {})
        for c in item["spec"].get("containers", []):
            csc = c.get("securityContext", {})
            # root if runAsUser==0, or runAsNonRoot not set/false, or allowPrivilegeEscalation
            is_root = (
                csc.get("runAsUser") == 0
                or csc.get("runAsNonRoot") is False
                or (
                    "runAsNonRoot" not in csc
                    and "runAsUser" not in csc
                    and not pod_sc.get("runAsNonRoot")
                )
            )
            if is_root:
                findings.append({
                    "namespace": ns,
                    "resource_name": name,
                    "resource_type": "Pod",
                    "description": (
                        f"Container '{c['name']}' in pod '{name}' (ns: {ns}) "
                        "may run as root. securityContext.runAsNonRoot is not enforced."
                    ),
                })
    return findings


def detect_missing_network_policies(namespaces_json: Dict, cluster: str) -> List[Dict]:
    findings = []
    ns_names = [
        item["metadata"]["name"]
        for item in namespaces_json.get("items", [])
        if item["metadata"]["name"] not in ("kube-system", "kube-public", "kube-node-lease")
    ]
    for ns in ns_names:
        netpol_json = _kubectl_json(
            f"kubectl get networkpolicies -n {ns} -o json --context kind-{cluster}"
        )
        policies = (netpol_json or {}).get("items", [])
        if not policies:
            findings.append({
                "namespace": ns,
                "resource_name": ns,
                "resource_type": "Namespace",
                "description": (
                    f"Namespace '{ns}' has no NetworkPolicy. "
                    "All pod-to-pod traffic is allowed."
                ),
            })
    return findings


_SECRET_PATTERNS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "auth", "credential", "private_key", "access_key",
]


def detect_plaintext_secrets(pods_json: Dict, cluster: str) -> List[Dict]:
    findings = []
    for item in pods_json.get("items", []):
        ns = item["metadata"]["namespace"]
        name = item["metadata"]["name"]
        for c in item["spec"].get("containers", []):
            for env in c.get("env", []):
                env_name = env.get("name", "").lower()
                # Only flag if it's a literal value (not a secretKeyRef/configMapKeyRef)
                if "value" in env and not env.get("valueFrom"):
                    if any(pat in env_name for pat in _SECRET_PATTERNS):
                        findings.append({
                            "namespace": ns,
                            "resource_name": name,
                            "resource_type": "Pod",
                            "description": (
                                f"Container '{c['name']}' in pod '{name}' (ns: {ns}) "
                                f"has sensitive env var '{env['name'].upper()}' set as plaintext. "
                                "Use secretKeyRef instead."
                            ),
                        })
    return findings


def detect_cluster_admin_bindings(crb_json: Dict, cluster: str) -> List[Dict]:
    findings = []
    for item in crb_json.get("items", []):
        role_ref = item.get("roleRef", {})
        if role_ref.get("name") == "cluster-admin":
            subjects = item.get("subjects", [])
            for subj in subjects:
                if subj.get("name") in ("system:anonymous", "system:unauthenticated"):
                    # highest severity — anonymous cluster-admin
                    findings.append({
                        "namespace": "cluster-wide",
                        "resource_name": item["metadata"]["name"],
                        "resource_type": "ClusterRoleBinding",
                        "description": (
                            f"ClusterRoleBinding '{item['metadata']['name']}' grants "
                            f"cluster-admin to '{subj['name']}' (unauthenticated access)."
                        ),
                    })
                elif subj.get("kind") != "ServiceAccount" or not subj.get("name", "").startswith("system:"):
                    findings.append({
                        "namespace": subj.get("namespace", "cluster-wide"),
                        "resource_name": item["metadata"]["name"],
                        "resource_type": "ClusterRoleBinding",
                        "description": (
                            f"ClusterRoleBinding '{item['metadata']['name']}' grants "
                            f"cluster-admin to {subj.get('kind','?')} '{subj.get('name','?')}'. "
                            "Review whether this level of access is required."
                        ),
                    })
    return findings


def detect_anonymous_auth(kube_system_pods_json: Dict, cluster: str) -> List[Dict]:
    findings = []
    for item in kube_system_pods_json.get("items", []):
        name = item["metadata"]["name"]
        if "kube-apiserver" not in name:
            continue
        for c in item["spec"].get("containers", []):
            cmd = c.get("command", []) + c.get("args", [])
            has_anon_false = any("--anonymous-auth=false" in arg for arg in cmd)
            if not has_anon_false:
                findings.append({
                    "namespace": "kube-system",
                    "resource_name": name,
                    "resource_type": "Pod",
                    "description": (
                        f"API server pod '{name}' does not explicitly set "
                        "--anonymous-auth=false. Anonymous requests may be permitted."
                    ),
                })
    return findings


# Map detect_fn name -> function
DETECT_FNS = {
    "detect_no_resource_limits": detect_no_resource_limits,
    "detect_root_containers": detect_root_containers,
    "detect_missing_network_policies": detect_missing_network_policies,
    "detect_plaintext_secrets": detect_plaintext_secrets,
    "detect_cluster_admin_bindings": detect_cluster_admin_bindings,
    "detect_anonymous_auth": detect_anonymous_auth,
}

# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------


@dataclass
class RunReport:
    cluster: str
    org_id: str
    dry_run: bool
    cluster_registered: bool = False
    cluster_id: Optional[str] = None
    workloads_deployed: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    posted_findings: int = 0
    failed_posts: int = 0
    cis_result: Optional[Dict] = None
    errors: List[str] = field(default_factory=list)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: Optional[str] = None


def ensure_cluster(cluster_name: str, dry_run: bool) -> bool:
    """Return True if cluster is reachable, creating it if needed."""
    result = _run("kind get clusters", check=False)
    existing = result.stdout.strip().splitlines()
    if cluster_name in existing:
        log.info("Kind cluster '%s' already exists.", cluster_name)
        return True

    if dry_run:
        log.info("[DRY-RUN] Would create kind cluster '%s' with 3 nodes.", cluster_name)
        return True

    log.info("Creating kind cluster '%s' (3-node)…", cluster_name)
    config_path = Path(f"/tmp/kind-config-{cluster_name}.yaml")
    config_path.write_text(KIND_CONFIG)
    try:
        _run(
            f"kind create cluster --name {cluster_name} --config {config_path}",
            timeout=300,
        )
        log.info("Cluster created.")
        return True
    except subprocess.CalledProcessError as exc:
        log.error("Failed to create cluster: %s", exc.stderr)
        return False


def deploy_insecure_workloads(cluster: str, dry_run: bool) -> List[str]:
    """Apply insecure workload manifests to the cluster."""
    deployed = []
    for wl in INSECURE_WORKLOADS:
        manifest_json = json.dumps(wl["manifest"])
        cmd = f"echo '{manifest_json}' | kubectl apply -f - --context kind-{cluster}"
        if dry_run:
            log.info(
                "[DRY-RUN] Would deploy '%s' — %s", wl["name"], wl["description"]
            )
            deployed.append(wl["name"])
            continue
        try:
            result = _run(cmd, check=False, timeout=30)
            if result.returncode == 0:
                log.info("Deployed: %s", wl["name"])
                deployed.append(wl["name"])
            else:
                log.warning("Deploy failed for '%s': %s", wl["name"], result.stderr.strip())
        except Exception as exc:
            log.warning("Deploy error for '%s': %s", wl["name"], exc)
    return deployed


def register_cluster_in_aldeci(
    cluster: str, org_id: str, base_url: str, dry_run: bool
) -> Optional[str]:
    """Register the kind cluster in ALDECI, return cluster_id."""
    # Count actual nodes
    node_count = 3  # default
    if not dry_run:
        result = _run(
            f"kubectl get nodes --context kind-{cluster} --no-headers 2>/dev/null | wc -l",
            check=False,
        )
        try:
            node_count = int(result.stdout.strip())
        except ValueError:
            pass

    body = {
        "cluster_name": cluster,
        "provider": "kind",
        "k8s_version": "1.35.0",
        "node_count": node_count,
        "namespace_count": 5,
    }
    resp = _api(
        "POST",
        f"/api/v1/kubernetes-security/clusters?org_id={org_id}",
        base_url,
        body=body,
        dry_run=dry_run,
    )
    if resp:
        cluster_id = resp.get("id") or resp.get("cluster_id")
        log.info("Cluster registered in ALDECI — id: %s", cluster_id)
        return cluster_id
    log.error("Failed to register cluster in ALDECI.")
    return None


def run_cis_checks(cluster: str, dry_run: bool) -> List[Dict]:
    """Execute all CIS checks against the cluster and return raw findings."""
    all_findings: List[Dict] = []
    # Cache kubectl calls that are shared across checks
    _cache: Dict[str, Any] = {}

    for check in CIS_CHECKS:
        cmd = check.kubectl_check.format(cluster=cluster)
        if dry_run:
            log.info("[DRY-RUN] CIS %s — %s", check.cis_id, check.title)
            # Simulate one finding per check in dry-run mode
            all_findings.append({
                "cis_control": check.cis_id,
                "severity": check.severity,
                "finding_type": check.finding_type,
                "remediation": check.remediation,
                "namespace": "default",
                "resource_name": f"dry-run-resource-{check.cis_id}",
                "resource_type": "Pod",
                "description": f"[DRY-RUN] Simulated finding for CIS {check.cis_id}: {check.title}",
                "check_title": check.title,
            })
            continue

        log.info("Running CIS %s: %s", check.cis_id, check.title)
        if cmd not in _cache:
            _cache[cmd] = _kubectl_json(cmd)
        data = _cache[cmd]
        if data is None:
            log.warning("  Skipping — kubectl returned no data.")
            continue

        detect_fn = DETECT_FNS.get(check.detect_fn)
        if detect_fn is None:
            log.warning("  Unknown detect_fn: %s", check.detect_fn)
            continue

        raw_findings = detect_fn(data, cluster)
        log.info("  Found %d issue(s).", len(raw_findings))
        for f in raw_findings:
            all_findings.append({
                "cis_control": check.cis_id,
                "severity": check.severity,
                "finding_type": check.finding_type,
                "remediation": check.remediation,
                "check_title": check.title,
                **f,
            })

    return all_findings


def post_findings_to_aldeci(
    findings: List[Dict],
    cluster_id: str,
    org_id: str,
    base_url: str,
    dry_run: bool,
) -> Tuple[int, int]:
    """POST each finding to ALDECI. Returns (posted, failed)."""
    posted = 0
    failed = 0
    for f in findings:
        body = {
            "cluster_id": cluster_id,
            "finding_type": f.get("finding_type", "misconfiguration"),
            "severity": f.get("severity", "medium"),
            "namespace": f.get("namespace", "default"),
            "resource_name": f.get("resource_name", ""),
            "resource_type": f.get("resource_type", ""),
            "description": f.get("description", ""),
            "remediation": f.get("remediation", ""),
        }
        resp = _api(
            "POST",
            f"/api/v1/kubernetes-security/findings?org_id={org_id}",
            base_url,
            body=body,
            dry_run=dry_run,
        )
        if resp:
            posted += 1
        else:
            failed += 1
        time.sleep(0.1)  # gentle rate limiting
    return posted, failed


def trigger_cis_benchmark(
    cluster_id: str, org_id: str, base_url: str, dry_run: bool
) -> Optional[Dict]:
    """Hit /clusters/{id}/cis-benchmark to record the benchmark run."""
    return _api(
        "POST",
        f"/api/v1/kubernetes-security/clusters/{cluster_id}/cis-benchmark?org_id={org_id}",
        base_url,
        dry_run=dry_run,
    )


def print_report(report: RunReport) -> None:
    """Print a human-readable summary."""
    sep = "=" * 70
    print(f"\n{sep}")
    print("  ALDECI CSPM — Kind Cluster Scan Report")
    print(sep)
    print(f"  Cluster   : kind-{report.cluster}")
    print(f"  Org       : {report.org_id}")
    print(f"  Dry-run   : {report.dry_run}")
    print(f"  Started   : {report.started_at}")
    print(f"  Finished  : {report.finished_at}")
    print()

    print(f"  Workloads deployed : {len(report.workloads_deployed)}")
    for wl in report.workloads_deployed:
        print(f"    • {wl}")

    print()
    print(f"  Findings detected  : {len(report.findings)}")
    print(f"  Posted to ALDECI   : {report.posted_findings}")
    print(f"  Failed posts       : {report.failed_posts}")
    print()

    # Group by severity
    by_severity: Dict[str, List[Dict]] = {}
    for f in report.findings:
        sev = f.get("severity", "unknown")
        by_severity.setdefault(sev, []).append(f)

    for sev in ("critical", "high", "medium", "low"):
        items = by_severity.get(sev, [])
        if not items:
            continue
        print(f"  {sev.upper()} ({len(items)})")
        for f in items:
            cis = f.get("cis_control", "?")
            desc = f.get("description", "")
            ns = f.get("namespace", "")
            res = f.get("resource_name", "")
            print(f"    [{cis}] {ns}/{res}")
            print(f"           {desc[:120]}")
        print()

    if report.cis_result:
        print("  CIS Benchmark trigger: OK")
        if isinstance(report.cis_result, dict):
            score = report.cis_result.get("score") or report.cis_result.get("pass_pct")
            if score is not None:
                print(f"    Score: {score}")
    else:
        print("  CIS Benchmark trigger: not available (API offline or dry-run)")

    if report.errors:
        print()
        print(f"  Errors ({len(report.errors)}):")
        for e in report.errors:
            print(f"    ! {e}")

    print()
    print(sep)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ALDECI CSPM test harness for local kind clusters."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without touching the cluster or API.",
    )
    parser.add_argument(
        "--cluster",
        default=DEFAULT_CLUSTER,
        help=f"Kind cluster name (default: {DEFAULT_CLUSTER})",
    )
    parser.add_argument(
        "--aldeci-url",
        default=DEFAULT_URL,
        help=f"ALDECI base URL (default: {DEFAULT_URL})",
    )
    parser.add_argument(
        "--org-id",
        default=DEFAULT_ORG,
        help=f"Organisation ID (default: {DEFAULT_ORG})",
    )
    parser.add_argument(
        "--skip-deploy",
        action="store_true",
        help="Skip deploying insecure workloads (if already deployed).",
    )
    args = parser.parse_args()

    report = RunReport(
        cluster=args.cluster,
        org_id=args.org_id,
        dry_run=args.dry_run,
    )

    log.info("ALDECI CSPM Kind Cluster Test — %s", "DRY-RUN" if args.dry_run else "LIVE")
    log.info("Cluster: kind-%s  |  URL: %s  |  Org: %s", args.cluster, args.aldeci_url, args.org_id)

    # 1. Ensure cluster exists
    if not ensure_cluster(args.cluster, args.dry_run):
        report.errors.append("Could not ensure kind cluster exists.")
        report.finished_at = datetime.now(timezone.utc).isoformat()
        print_report(report)
        return 1

    # 2. Deploy insecure workloads
    if not args.skip_deploy:
        log.info("Deploying %d intentionally insecure workloads…", len(INSECURE_WORKLOADS))
        report.workloads_deployed = deploy_insecure_workloads(args.cluster, args.dry_run)
        if not args.dry_run and report.workloads_deployed:
            log.info("Waiting 5s for pods to be scheduled…")
            time.sleep(5)
    else:
        log.info("--skip-deploy set, skipping workload deployment.")

    # 3. Register cluster in ALDECI
    log.info("Registering cluster in ALDECI…")
    cluster_id = register_cluster_in_aldeci(
        args.cluster, args.org_id, args.aldeci_url, args.dry_run
    )
    if cluster_id:
        report.cluster_registered = True
        report.cluster_id = cluster_id
    else:
        cluster_id = f"dry-{uuid.uuid4().hex[:8]}" if args.dry_run else "unknown"
        report.errors.append("Cluster registration failed — using placeholder ID.")

    # 4. Run CIS benchmark checks
    log.info("Running %d CIS Kubernetes benchmark checks…", len(CIS_CHECKS))
    report.findings = run_cis_checks(args.cluster, args.dry_run)
    log.info("Total findings: %d", len(report.findings))

    # 5. POST findings to ALDECI
    if report.findings:
        log.info("Posting findings to ALDECI…")
        report.posted_findings, report.failed_posts = post_findings_to_aldeci(
            report.findings, cluster_id, args.org_id, args.aldeci_url, args.dry_run
        )

    # 6. Trigger CIS benchmark endpoint
    log.info("Triggering ALDECI CIS benchmark for cluster %s…", cluster_id)
    report.cis_result = trigger_cis_benchmark(
        cluster_id, args.org_id, args.aldeci_url, args.dry_run
    )

    report.finished_at = datetime.now(timezone.utc).isoformat()
    print_report(report)

    # Exit 1 if any critical findings and not dry-run (so CI can catch it)
    critical_count = sum(1 for f in report.findings if f.get("severity") == "critical")
    if critical_count > 0 and not args.dry_run:
        log.warning("%d critical finding(s) — exiting with code 1.", critical_count)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
