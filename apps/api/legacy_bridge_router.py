"""
Legacy API Bridge Router

This module bridges legacy APIs from archive/enterprise_legacy/src/api/v1/
into the main apps/api application. It uses sys.path manipulation to import
the legacy modules without modifying their internal imports.

Legacy APIs bridged (unique functionality not duplicated elsewhere):
- business_context_enhanced: SBOM context upload (works)
- feeds: CVE/KEV feed status (works)
- processing_layer: Bayesian/Markov/Fusion testing (works)
- production_readiness: Production readiness checks (works)
- sample_data_demo: Demo data generation (works)
- system_mode: Demo/Enterprise mode toggle (works)

Legacy APIs NOT bridged (missing dependencies or already covered):
- business_context: requires bcrypt (not installed)
- cicd: requires sqlalchemy (not installed)
- decisions: requires bcrypt (not installed)
- marketplace: hardcoded /app path
- oss_tools: hardcoded /app path
- scans: requires sqlalchemy (not installed)
- monitoring: duplicated by health_router
- evidence: duplicated by backend/api/evidence
- policy: duplicated by policies_router
- docs: built-in FastAPI /docs
- system: duplicated by health_router
- enhanced: may overlap with pentagi_router_enhanced
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from fastapi import APIRouter

logger = logging.getLogger(__name__)

# Calculate the path to the legacy parent directory (archive/enterprise_legacy)
# This allows 'from src.*' imports to work in the legacy modules
LEGACY_PARENT_PATH = (
    Path(__file__).parent.parent.parent / "archive" / "enterprise_legacy"
)

# Set environment variables to avoid hardcoded /app path issues in legacy code
os.environ.setdefault("FIXOPS_FEEDS_DIR", "/tmp/fixops_data/feeds")
os.environ.setdefault("FIXOPS_DATA_DIR", "/tmp/fixops_data")
os.environ.setdefault("ML_MODEL_PATH", "/tmp/models")

router = APIRouter(tags=["legacy"])


def _import_legacy_routers():
    """
    Import legacy routers by adding the legacy parent path to sys.path.
    This allows the legacy modules to use their original 'from src.*' imports.
    """
    legacy_routers = {}

    # Add legacy parent path to sys.path so 'src' becomes a package
    legacy_path_str = str(LEGACY_PARENT_PATH)
    if legacy_path_str not in sys.path:
        sys.path.insert(0, legacy_path_str)

    # Import each legacy router module
    # Note: We import them one by one and catch errors individually
    # so that a failure in one doesn't prevent others from loading

    # Only include modules that are known to work without additional dependencies
    legacy_modules = [
        ("business_context_enhanced", "src.api.v1.business_context_enhanced"),
        ("feeds", "src.api.v1.feeds"),
        ("processing_layer", "src.api.v1.processing_layer"),
        ("production_readiness", "src.api.v1.production_readiness"),
        ("sample_data_demo", "src.api.v1.sample_data_demo"),
        ("system_mode", "src.api.v1.system_mode"),
    ]

    for name, module_path in legacy_modules:
        try:
            module = __import__(module_path, fromlist=["router"])
            if hasattr(module, "router"):
                legacy_routers[name] = module.router
                logger.info(f"Loaded legacy router: {name}")
            else:
                logger.warning(f"Legacy module {name} has no router attribute")
        except Exception as e:
            logger.warning(f"Failed to import legacy router {name}: {e}")

    return legacy_routers


# Import legacy routers at module load time
_legacy_routers = {}

try:
    _legacy_routers = _import_legacy_routers()
except Exception as e:
    logger.error(f"Failed to import legacy routers: {e}")


# Include each legacy router with its original prefix
# The legacy routers already have their own prefix (e.g., /business-context, /feeds)
# We add /api/v1 prefix to match the original legacy app structure
for name, legacy_router in _legacy_routers.items():
    try:
        router.include_router(
            legacy_router,
            prefix="/api/v1",
            tags=[f"legacy-{name}"],
        )
        logger.info(
            f"Registered legacy router: {name} at /api/v1{legacy_router.prefix}"
        )
    except Exception as e:
        logger.warning(f"Failed to register legacy router {name}: {e}")


def get_legacy_router_status():
    """Return status of loaded legacy routers for health checks."""
    return {
        "loaded_routers": list(_legacy_routers.keys()),
        "total_loaded": len(_legacy_routers),
        "expected_routers": 6,  # Only 6 legacy modules are bridged (see legacy_modules list)
    }
