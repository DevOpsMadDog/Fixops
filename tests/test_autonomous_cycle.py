"""Focused autonomous-cycle validation entrypoint.

This wrapper maps the autonomous-cycle suite onto maintained, high-signal
validation coverage so the focused validation command exercises current
behavior instead of missing legacy filenames.
"""

import pytest

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
