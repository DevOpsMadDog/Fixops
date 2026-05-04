"""
test_engine_router_import_sweep.py
===================================
Parametrized import-sanity sweep for every engine, service, manager, and router
in the ALDECI codebase.

Why: With 463 engines + 796 routers, a single ImportError or SyntaxError silently
kills that module's endpoints. This test catches those failures before they reach
production, one test row per file.

Strategy:
- Use importlib.util.spec_from_file_location so each module loads in isolation.
- Known optional-dep failures (boto3, google.cloud, snowflake, etc.) → pytest.skip.
- Everything else → genuine test failure (real bug, fix it).

Run:
    python -m pytest tests/test_engine_router_import_sweep.py -x --tb=short --timeout=30 -q -o "addopts="
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

# ── Project root ─────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent.resolve()

# ── Ensure sitecustomize paths are wired (mirrors production path setup) ─────
_SUITE_PATHS = [
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-integrations",
    "suite-evidence-risk",
]
for _suite in _SUITE_PATHS:
    _p = str(PROJECT_ROOT / _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── File globs to sweep ───────────────────────────────────────────────────────
_GLOBS = [
    (PROJECT_ROOT / "suite-core" / "core",     "*_engine.py"),
    (PROJECT_ROOT / "suite-core" / "core",     "*_service.py"),
    (PROJECT_ROOT / "suite-core" / "core",     "*_manager.py"),
    (PROJECT_ROOT / "suite-api"  / "apps/api", "*_router.py"),
    (PROJECT_ROOT / "suite-core" / "api",      "*_router.py"),
]

def _collect_files() -> list[Path]:
    files: list[Path] = []
    for base, pattern in _GLOBS:
        if base.is_dir():
            files.extend(sorted(base.glob(pattern)))
    # deduplicate by absolute path (shouldn't overlap, but just in case)
    seen: set[Path] = set()
    unique: list[Path] = []
    for f in files:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique

_ALL_FILES = _collect_files()

# ── Optional-dependency allowlist ─────────────────────────────────────────────
# If an ImportError's missing-module name contains any of these strings,
# we skip rather than fail — the dep is an optional paid/heavy SDK.
_OPTIONAL_DEP_PREFIXES = (
    "boto3",
    "botocore",
    "google.cloud",
    "google.auth",
    "googleapiclient",
    "snowflake",
    "cx_Oracle",
    "oracledb",
    "pyodbc",
    "psycopg2",        # may not be installed in lightweight CI
    "asyncpg",
    "aiomysql",
    "pymysql",
    "motor",           # MongoDB async
    "pymongo",
    "redis",
    "celery",
    "confluent_kafka",
    "kafka",
    "pyspark",
    "torch",
    "tensorflow",
    "cv2",
    "sklearn",
    "scipy",
    "ldap3",
    "saml2",
    "azure.identity",
    "azure.mgmt",
    "okta",
    "duo_client",
    "qualys",
    "tenable",
    "crowdstrike",
    "falconpy",
    "rapid7",
    "veracode",
    "checkmarx",
    "fortify",
    "contrast",
    "datadog",
    "newrelic",
    "splunk",
    "elasticsearch",
    "opensearch",
    "jira",
    "servicenow",
    "pagerduty",
    "slack_sdk",
    "twilio",
    "sendgrid",
    "stripe",
    "kubernetes",
    "docker",
    "paramiko",
    "fabric",
    "ansible",
    "terraform",
    "pulumi",
    "cdktf",
    "nmap",
    "scapy",
    "shodan",
    "censys",
    "virustotal",
    "plyvel",
    "lancedb",
    "duckdb",           # optional analytics dep
    "weaviate",
    "qdrant_client",
    "pinecone",
    "chromadb",
)

def _is_optional_dep_error(exc: ImportError) -> bool:
    """Return True if the ImportError is due to a known optional external SDK."""
    msg = str(exc)
    # Python ImportError carries the missing module name in exc.name for ModuleNotFoundError
    missing = getattr(exc, "name", None) or ""
    combined = f"{msg} {missing}".lower()
    for prefix in _OPTIONAL_DEP_PREFIXES:
        if prefix.lower() in combined:
            return True
    return False


# ── Parametrize ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "filepath",
    _ALL_FILES,
    ids=[f.stem for f in _ALL_FILES],
)
def test_module_imports_clean(filepath: Path) -> None:
    """Assert that importing the module raises no ImportError or SyntaxError."""
    module_name = f"_sweep_{filepath.stem}"

    # Load spec from absolute file path — independent of package __init__ chains
    spec = importlib.util.spec_from_file_location(module_name, filepath)
    if spec is None or spec.loader is None:
        pytest.skip(f"Cannot create spec for {filepath} — skipping")

    module = importlib.util.module_from_spec(spec)
    # Register in sys.modules so relative imports inside the module resolve
    sys.modules[module_name] = module

    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except ImportError as exc:
        if _is_optional_dep_error(exc):
            missing = getattr(exc, "name", str(exc))
            pytest.skip(f"Optional dep not installed: {missing}")
        # Real import error — this is a bug
        raise
    except SyntaxError:
        raise
    except Exception:
        # Runtime errors during module-level code (e.g. DB connection at import
        # time) are NOT import errors — let them surface as failures too.
        raise
    finally:
        # Clean up so the next parametrized run gets a fresh module object
        sys.modules.pop(module_name, None)
