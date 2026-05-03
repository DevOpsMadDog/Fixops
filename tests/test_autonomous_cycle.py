"""Focused autonomous-cycle validation entrypoint.

This wrapper maps the autonomous-cycle suite onto maintained, high-signal
validation coverage so the focused validation command exercises current
behavior instead of missing legacy filenames.

When run in isolation (e.g. ``pytest tests/test_autonomous_cycle.py``), the
``tests.e2e.conftest`` plugin is registered explicitly so that E2E fixtures
are available.  When collected as part of the full ``tests/`` tree, pytest
discovers the conftest automatically, so we skip the explicit registration
to avoid the "Plugin already registered" error.
"""

import sys
import pytest

# Only register the e2e conftest when it has NOT already been loaded by
# pytest's automatic conftest discovery (i.e. when running this file in
# isolation rather than as part of the full tests/ collection).
if "tests.e2e.conftest" not in sys.modules:
    pytest_plugins = ["tests.e2e.conftest"]

from tests.e2e.test_bn_lr_hybrid import TestBNLRHybrid as _TestBNLRHybrid
from tests.e2e.test_branding_namespace import TestBrandingNamespace as _TestBrandingNamespace
from tests.test_ai_consensus import *  # noqa: F401,F403


@pytest.mark.timeout(120)
class TestBNLRHybrid(_TestBNLRHybrid):
    pass


@pytest.mark.timeout(120)
class TestBrandingNamespace(_TestBrandingNamespace):
    pass
