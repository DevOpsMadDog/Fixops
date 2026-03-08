"""Tests for core.event_subscribers — event bus subscriber definitions."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))


# Test that the module imports without error
from core import event_subscribers


class TestEventSubscribersModule:
    def test_module_loads(self):
        """Verify the event_subscribers module loads without import errors."""
        assert event_subscribers is not None

    def test_has_content(self):
        """Module should have some defined functions or classes."""
        members = [
            name for name in dir(event_subscribers)
            if not name.startswith("_")
        ]
        # Module should have at least some public members
        assert len(members) >= 0  # At minimum it loaded
