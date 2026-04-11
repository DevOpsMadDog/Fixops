"""Focused autonomous-foundation validation entrypoint.

This wrapper re-exports foundational configuration and app-factory coverage
that is actively maintained in the repository.
"""

from tests.test_app_factory import *  # noqa: F401,F403
from tests.test_configuration_unit import *  # noqa: F401,F403
from tests.test_overlay_configuration import *  # noqa: F401,F403
from tests.test_overlay_runtime import *  # noqa: F401,F403
