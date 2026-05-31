"""Smoke harness for 38 legacy connector routers — customer-readiness gate B2.

Tests are fully self-contained:
  - A minimal FastAPI app is created per session with all routers mounted.
  - All external-credential env vars are UNSET so every cred-gated endpoint
    returns 503 (not_configured / unavailable pattern).
  - Auth is exercised with a known token (X-API-Key: smoke-test-token).
  - Missing-auth probes verify 401 on a representative endpoint per router.

Special cases documented inline:
  - kong_router, workday_router, purview_dlp_router, noname_router,
    lacework_router, orca_router, splunk_soar_router, pyrit_router:
    no api_key_auth dependency in router declaration (auth at mount layer);
    401 test is skipped with pytest.mark.skip for those routers.
  - imperva_router: credential endpoints accept form-encoded params that
    are validated before cred-check; 503 test uses GET /api/v3/policies
    which requires the accountId query param.

Coverage per router (3 tests each):
  1. GET /api/v1/<prefix>/  → 200 + 'status' field present
  2. One cred-gated endpoint  → 503 (unavailable)
  3. Auth gate: same endpoint, no X-API-Key → 401 (skipped for mount-auth routers)

Total target: ~114 tests.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Ensure suite-api is on sys.path (mirrors sitecustomize.py)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SUITE_API = _REPO_ROOT / "suite-api"
for _p in [str(_REPO_ROOT), str(_SUITE_API)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_API_KEY = "smoke-test-token"
_AUTH_HEADERS = {"X-API-Key": _API_KEY}
_NO_AUTH_HEADERS: dict[str, str] = {}

# Routers that do NOT declare api_key_auth at the router level (auth is added
# at the platform mount layer).  We skip the 401 test for these.
_MOUNT_AUTH_ROUTERS = frozenset(
    [
        "kong",
        "workday",
        "microsoft-purview",
        "noname",
        "lacework",
        "orca",
        "splunk-soar-rest",
        "pyrit",
    ]
)


def _clear_module_cache(*module_names: str) -> None:
    for name in module_names:
        for key in list(sys.modules.keys()):
            if key == name or key.startswith(name + "."):
                sys.modules.pop(key, None)


# ---------------------------------------------------------------------------
# Fixture: set auth env + unset all external creds
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module", autouse=True)
def _set_auth_env(tmp_path_factory: pytest.TempPathFactory) -> Any:
    """Set FIXOPS_API_TOKEN and unset every external-connector credential."""
    env_patch = {
        # Auth
        "FIXOPS_API_TOKEN": _API_KEY,
        "FIXOPS_MODE": "production",
        # --- WAF / CDN ---
        "IMPERVA_API_ID": "",
        "IMPERVA_API_KEY": "",
        "FASTLY_API_TOKEN": "",
        "AWS_ACCESS_KEY_ID": "",
        "AWS_SECRET_ACCESS_KEY": "",
        "AWS_REGION": "",
        # --- Identity / SSO ---
        "AUTH0_DOMAIN": "",
        "AUTH0_CLIENT_ID": "",
        "AUTH0_CLIENT_SECRET": "",
        "CYBERARK_URL": "",
        "CYBERARK_USERNAME": "",
        "CYBERARK_PASSWORD": "",
        "SAILPOINT_TENANT_URL": "",
        "SAILPOINT_CLIENT_ID": "",
        "SAILPOINT_CLIENT_SECRET": "",
        # --- Microsoft surfaces ---
        "AZURE_TENANT_ID": "",
        "AZURE_CLIENT_ID": "",
        "AZURE_CLIENT_SECRET": "",
        # --- EDR / XDR ---
        "SENTINELONE_URL": "",
        "SENTINELONE_API_TOKEN": "",
        # --- DLP / CASB / Proxy ---
        "NETSKOPE_TENANT_URL": "",
        "NETSKOPE_API_TOKEN": "",
        "ZSCALER_ZIA_BASE_URL": "",
        "ZSCALER_ZIA_USERNAME": "",
        "ZSCALER_ZIA_PASSWORD": "",
        "ZSCALER_ZIA_API_KEY": "",
        # --- Email security ---
        "PROOFPOINT_TAP_PRINCIPAL": "",
        "PROOFPOINT_TAP_SECRET": "",
        "MIMECAST_BASE_URL": "",
        "MIMECAST_APP_ID": "",
        "MIMECAST_APP_KEY": "",
        "MIMECAST_ACCESS_KEY": "",
        "MIMECAST_SECRET_KEY": "",
        # --- API security ---
        "NONAME_BASE_URL": "",
        "NONAME_CLIENT_ID": "",
        "NONAME_CLIENT_SECRET": "",
        "SALT_API_BASE": "",
        "SALT_CLIENT_ID": "",
        "SALT_CLIENT_SECRET": "",
        "APICRUNCH_API_TOKEN": "",
        "TRACEABLE_BASE_URL": "",
        "TRACEABLE_API_TOKEN": "",
        "AKTO_BASE_URL": "",
        "AKTO_API_TOKEN": "",
        # --- Asset / CSPM ---
        "JUPITERONE_API_KEY": "",
        "JUPITERONE_ACCOUNT": "",
        "LACEWORK_ACCOUNT": "",
        "LACEWORK_KEY_ID": "",
        "LACEWORK_SECRET": "",
        "ORCA_API_TOKEN": "",
        # --- API gateway ---
        "KONG_ADMIN_URL": "",
        "KONG_ADMIN_TOKEN": "",
        "APIGEE_ORG": "",
        "GOOGLE_APPLICATION_CREDENTIALS": "",
        # --- IaC / cloud ---
        "PULUMI_ACCESS_TOKEN": "",
        "CROSSPLANE_KUBECONFIG": "",
        "CROSSPLANE_KUBE_SERVER": "",
        # --- Vulnerability / SAST ---
        "QUALYS_USERNAME": "",
        "QUALYS_PASSWORD": "",
        "QUALYS_API_BASE": "",
        "CHECKMARX_BASE_URL": "",
        "CHECKMARX_CLIENT_ID": "",
        "CHECKMARX_CLIENT_SECRET": "",
        "CHECKMARX_TENANT": "",
        "CONTRAST_BASE_URL": "",
        "CONTRAST_API_KEY": "",
        "CONTRAST_AUTH_HEADER": "",
        "CONTRAST_SERVICE_KEY": "",
        # --- SOAR ---
        "SPLUNK_SOAR_URL": "",
        "SPLUNK_SOAR_TOKEN": "",
        "XSOAR_BASE_URL": "",
        "XSOAR_API_KEY": "",
        # --- Network ---
        "THOUSANDEYES_API_TOKEN": "",
        # --- Backup ---
        "VEEAM_BASE_URL": "",
        "VEEAM_USERNAME": "",
        "VEEAM_PASSWORD": "",
        # --- HCM ---
        "WORKDAY_TENANT": "",
        "WORKDAY_BASE_URL": "",
        "WORKDAY_USERNAME": "",
        "WORKDAY_PASSWORD": "",
        # --- LLM observability ---
        "LANGSMITH_API_KEY": "",
        "BRAINTRUST_API_KEY": "",
        "HELICONE_API_KEY": "",
        # --- AI security ---
        "PYRIT_RUNNER_URL": "",
        "GUARDRAILS_API_KEY": "",
    }

    originals = {k: os.environ.get(k) for k in env_patch}
    for k, v in env_patch.items():
        os.environ[k] = v

    _clear_module_cache("apps.api.auth_deps")

    yield

    for k, orig in originals.items():
        if orig is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = orig


# ---------------------------------------------------------------------------
# Fixture: build the TestClient once, mounting all 38 routers
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client(_set_auth_env: Any) -> TestClient:
    """Create a minimal FastAPI app with all 38 legacy connector routers."""
    from apps.api.imperva_router import router as imperva_router
    from apps.api.fastly_router import router as fastly_router
    from apps.api.aws_waf_router import router as aws_waf_router
    from apps.api.auth0_router import router as auth0_router
    from apps.api.defender_xdr_router import router as defender_xdr_router
    from apps.api.sentinelone_router import router as sentinelone_router
    from apps.api.cyberark_pam_router import router as cyberark_pam_router
    from apps.api.sailpoint_iga_router import router as sailpoint_iga_router
    from apps.api.purview_dlp_router import router as purview_dlp_router
    from apps.api.netskope_router import router as netskope_router
    from apps.api.proofpoint_tap_router import router as proofpoint_tap_router
    from apps.api.mimecast_router import router as mimecast_router
    from apps.api.zscaler_zia_router import router as zscaler_zia_router
    from apps.api.noname_router import router as noname_router
    from apps.api.salt_security_router import router as salt_security_router
    from apps.api.apicrunch_router import router as apicrunch_router
    from apps.api.traceable_router import router as traceable_router
    from apps.api.akto_router import router as akto_router
    from apps.api.jupiterone_router import router as jupiterone_router
    from apps.api.kong_router import router as kong_router
    from apps.api.apigee_router import router as apigee_router
    from apps.api.pulumi_router import router as pulumi_router
    from apps.api.crossplane_router import router as crossplane_router
    from apps.api.lacework_router import router as lacework_router
    from apps.api.orca_router import router as orca_router
    from apps.api.qualys_router import router as qualys_router
    from apps.api.checkmarx_router import router as checkmarx_router
    from apps.api.contrast_router import router as contrast_router
    from apps.api.splunk_soar_router import router as splunk_soar_router
    from apps.api.xsoar_router import router as xsoar_router
    from apps.api.thousandeyes_router import router as thousandeyes_router
    from apps.api.veeam_router import router as veeam_router
    from apps.api.workday_router import router as workday_router
    from apps.api.langsmith_router import router as langsmith_router
    from apps.api.braintrust_router import router as braintrust_router
    from apps.api.helicone_router import router as helicone_router
    from apps.api.pyrit_router import router as pyrit_router
    from apps.api.guardrails_router import router as guardrails_router

    app = FastAPI(title="legacy-connector-smoke-test")
    for r in [
        imperva_router,
        fastly_router,
        aws_waf_router,
        auth0_router,
        defender_xdr_router,
        sentinelone_router,
        cyberark_pam_router,
        sailpoint_iga_router,
        purview_dlp_router,
        netskope_router,
        proofpoint_tap_router,
        mimecast_router,
        zscaler_zia_router,
        noname_router,
        salt_security_router,
        apicrunch_router,
        traceable_router,
        akto_router,
        jupiterone_router,
        kong_router,
        apigee_router,
        pulumi_router,
        crossplane_router,
        lacework_router,
        orca_router,
        qualys_router,
        checkmarx_router,
        contrast_router,
        splunk_soar_router,
        xsoar_router,
        thousandeyes_router,
        veeam_router,
        workday_router,
        langsmith_router,
        braintrust_router,
        helicone_router,
        pyrit_router,
        guardrails_router,
    ]:
        app.include_router(r)

    return TestClient(app, raise_server_exceptions=True)


# ===========================================================================
# 1. IMPERVA
# ===========================================================================
class TestImpervaConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/imperva/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_policies_503_no_creds(self, client: TestClient) -> None:
        """GET /api/v3/policies requires accountId query param + creds."""
        r = client.get(
            "/api/v1/imperva/api/v3/policies",
            params={"accountId": "12345"},
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/imperva/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 2. FASTLY
# ===========================================================================
class TestFastlyConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/fastly/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_services_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/fastly/service", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/fastly/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 3. AWS WAF
# ===========================================================================
class TestAwsWafConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/aws-waf/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_web_acls_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/aws-waf/web-acls",
            params={"Scope": "REGIONAL"},
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/aws-waf/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 4. AUTH0
# ===========================================================================
class TestAuth0Connector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/auth0/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_users_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/auth0/api/v2/users", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/auth0/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 5. DEFENDER XDR
# ===========================================================================
class TestDefenderXdrConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/defender-xdr/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_alerts_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/defender-xdr/v1.0/security/alerts_v2",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/defender-xdr/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 6. SENTINELONE
# ===========================================================================
class TestSentinelOneConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/sentinelone/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_agents_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/sentinelone/web/api/v2.1/agents",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/sentinelone/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 7. CYBERARK PAM
# ===========================================================================
class TestCyberArkPamConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/cyberark-pam/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_accounts_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/cyberark-pam/PasswordVault/API/Accounts",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/cyberark-pam/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 8. SAILPOINT IGA
# ===========================================================================
class TestSailPointIgaConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/sailpoint-iga/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_identities_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/sailpoint-iga/v3/identities",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/sailpoint-iga/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 9. MICROSOFT PURVIEW DLP
# NOTE: no api_key_auth at router level — 401 test skipped.
# ===========================================================================
class TestMicrosoftPurviewDlp:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/microsoft-purview/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_dlp_policies_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/microsoft-purview/v1.0/security/dataLossPreventionPolicies",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    @pytest.mark.skip(reason="purview_dlp_router has no router-level api_key_auth — auth at mount layer")
    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/microsoft-purview/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 10. NETSKOPE
# ===========================================================================
class TestNetskopeConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/netskope/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_events_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/netskope/api/v2/events/data/page",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/netskope/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 11. PROOFPOINT TAP
# ===========================================================================
class TestProofpointTapConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/proofpoint-tap/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_siem_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/proofpoint-tap/v2/siem/all", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/proofpoint-tap/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 12. MIMECAST
# ===========================================================================
class TestMimecastConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/mimecast/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_siem_logs_503_no_creds(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/mimecast/api/audit/get-siem-logs",
            json={"data": [{"type": "gateway", "compress": False, "fileFormat": "json"}]},
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/mimecast/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 13. ZSCALER ZIA
# ===========================================================================
class TestZscalerZiaConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/zscaler-zia/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_url_categories_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/zscaler-zia/api/v1/urlCategories", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/zscaler-zia/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 14. NONAME
# NOTE: no api_key_auth at router level — 401 test skipped.
# ===========================================================================
class TestNonameConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/noname/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_apis_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/noname/api/v3/apis", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    @pytest.mark.skip(reason="noname_router has no router-level api_key_auth — auth at mount layer")
    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/noname/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 15. SALT SECURITY
# ===========================================================================
class TestSaltSecurityConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/salt-security/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_incidents_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/salt-security/api/v1/incidents", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/salt-security/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 16. APICRUNCH (42Crunch)
# ===========================================================================
class TestApicrunchConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/apicrunch/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_collections_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/apicrunch/api/v2/collections", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/apicrunch/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 17. TRACEABLE AI
# ===========================================================================
class TestTraceableConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/traceable/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_services_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/traceable/api/v1/services", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/traceable/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 18. AKTO
# ===========================================================================
class TestAktoConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/akto/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_discovered_apis_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/akto/api/discovered-apis", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/akto/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 19. JUPITERONE
# ===========================================================================
class TestJupiterOneConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/jupiterone/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_alerts_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/jupiterone/alerts", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/jupiterone/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 20. KONG ADMIN
# NOTE: no api_key_auth at router level — 401 test skipped.
# ===========================================================================
class TestKongConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/kong/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_services_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/kong/services", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    @pytest.mark.skip(reason="kong_router has no router-level api_key_auth — auth at mount layer")
    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/kong/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 21. APIGEE
# ===========================================================================
class TestApigeeConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/apigee/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_apis_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/apigee/v1/organizations/my-org/apis",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/apigee/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 22. PULUMI
# ===========================================================================
class TestPulumiConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/pulumi/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_user_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/pulumi/api/user", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/pulumi/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 23. CROSSPLANE
# ===========================================================================
class TestCrossplaneConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/crossplane/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_providers_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/crossplane/apis/pkg.crossplane.io/v1/providers",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/crossplane/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 24. LACEWORK
# NOTE: no api_key_auth at router level — 401 test skipped.
# ===========================================================================
class TestLaceworkConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/lacework/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_alerts_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/lacework/api/v2/Alerts", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    @pytest.mark.skip(reason="lacework_router has no router-level api_key_auth — auth at mount layer")
    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/lacework/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 25. ORCA SECURITY
# NOTE: no api_key_auth at router level — 401 test skipped.
# ===========================================================================
class TestOrcaConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/orca/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_alerts_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/orca/api/alerts", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    @pytest.mark.skip(reason="orca_router has no router-level api_key_auth — auth at mount layer")
    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/orca/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 26. QUALYS VMDR
# ===========================================================================
class TestQualysConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/qualys/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_hosts_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/qualys/api/2.0/fo/asset/host/",
            params={"action": "list"},
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/qualys/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 27. CHECKMARX
# ===========================================================================
class TestCheckmarxConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/checkmarx/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_projects_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/checkmarx/api/projects", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/checkmarx/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 28. CONTRAST SECURITY
# ===========================================================================
class TestContrastConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/contrast/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_applications_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/contrast/api/ng/smoke-org/applications",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/contrast/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 29. SPLUNK SOAR
# NOTE: no api_key_auth at router level — 401 test skipped.
# ===========================================================================
class TestSplunkSoarConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/splunk-soar-rest/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_playbooks_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/splunk-soar-rest/rest/playbook", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    @pytest.mark.skip(reason="splunk_soar_router has no router-level api_key_auth — auth at mount layer")
    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/splunk-soar-rest/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 30. CORTEX XSOAR
# ===========================================================================
class TestXsoarConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/xsoar/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_incidents_search_503_no_creds(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/xsoar/incidents/search",
            json={"filter": {}},
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/xsoar/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 31. THOUSANDEYES
# ===========================================================================
class TestThousandEyesConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/thousandeyes/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_tests_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/thousandeyes/v6/tests.json", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/thousandeyes/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 32. VEEAM
# ===========================================================================
class TestVeeamConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/veeam/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_jobs_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/veeam/api/v1/jobs", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/veeam/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 33. WORKDAY
# NOTE: no api_key_auth at router level — 401 test skipped.
# ===========================================================================
class TestWorkdayConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/workday/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_workers_503_no_creds(self, client: TestClient) -> None:
        r = client.get(
            "/api/v1/workday/ccx/api/staffing/v6/smoke-tenant/workers",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    @pytest.mark.skip(reason="workday_router has no router-level api_key_auth — auth at mount layer")
    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/workday/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 34. LANGSMITH
# ===========================================================================
class TestLangSmithConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/langsmith/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_runs_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/langsmith/api/v1/runs", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/langsmith/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 35. BRAINTRUST
# ===========================================================================
class TestBraintrustConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/braintrust/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_experiments_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/braintrust/v1/experiment", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/braintrust/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 36. HELICONE
# ===========================================================================
class TestHeliconeConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/helicone/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_dataset_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/helicone/v1/dataset", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/helicone/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 37. PYRIT (Microsoft)
# NOTE: no api_key_auth at router level — 401 test skipped.
# ===========================================================================
class TestPyritConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/pyrit/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_attack_run_503_no_creds(self, client: TestClient) -> None:
        """POST /api/v1/attacks/run → 503 when PYRIT_RUNNER_URL unset."""
        r = client.post(
            "/api/v1/pyrit/api/v1/attacks/run",
            json={
                "orchestrator": "PromptSendingOrchestrator",
                "target": {"name": "OpenAIChatTarget", "params": {}},
                "prompts": [{"value": "smoke", "data_type": "text"}],
            },
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 503, r.text

    @pytest.mark.skip(reason="pyrit_router has no router-level api_key_auth — auth at mount layer")
    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/pyrit/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text


# ===========================================================================
# 38. GUARDRAILS AI
# ===========================================================================
class TestGuardrailsConnector:
    def test_info_200_has_status(self, client: TestClient) -> None:
        r = client.get("/api/v1/guardrails/", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert "status" in r.json()

    def test_specs_503_no_creds(self, client: TestClient) -> None:
        r = client.get("/api/v1/guardrails/v1/specs", headers=_AUTH_HEADERS)
        assert r.status_code == 503, r.text

    def test_info_401_no_auth(self, client: TestClient) -> None:
        r = client.get("/api/v1/guardrails/", headers=_NO_AUTH_HEADERS)
        assert r.status_code == 401, r.text
