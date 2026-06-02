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

# NOTE: the e2e suites (tests/e2e/test_bn_lr_hybrid.py, test_branding_namespace.py)
# are intentionally NOT re-exported here. Their fixtures (fixture_manager,
# cli_runner) live in tests/e2e/conftest.py, and pytest conftest fixtures are
# directory-scoped — they do NOT propagate up to tests/. Re-exporting those test
# classes here errored with "fixture 'cli_runner' not found" for all 16 cases.
# Those suites run (and pass) in their own directory.
from tests.test_ai_consensus import *  # noqa: F401,F403
