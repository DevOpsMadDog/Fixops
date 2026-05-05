"""Focused autonomous-cycle validation entrypoint.

This wrapper maps the autonomous-cycle suite onto maintained, high-signal
validation coverage so the focused validation command exercises current
behavior instead of missing legacy filenames.
"""

import pytest

# NOTE: do NOT declare pytest_plugins = ["tests.e2e.conftest"] here.
# When running the full test suite, pytest auto-discovers tests/e2e/conftest.py
# as a conftest and registers it under its file path key.  A pytest_plugins
# declaration in a non-conftest module would try to register the same module
# under its dotted-name key, triggering "Plugin already registered under a
# different name" (pluggy ValueError).  The fixtures we need from e2e/conftest
# are available automatically via pytest's conftest discovery.

from tests.e2e.test_bn_lr_hybrid import TestBNLRHybrid as _TestBNLRHybrid
from tests.e2e.test_branding_namespace import TestBrandingNamespace as _TestBrandingNamespace
from tests.test_ai_consensus import *  # noqa: F401,F403


@pytest.mark.timeout(120)
class TestBNLRHybrid(_TestBNLRHybrid):
    pass


@pytest.mark.timeout(120)
class TestBrandingNamespace(_TestBrandingNamespace):
    pass
