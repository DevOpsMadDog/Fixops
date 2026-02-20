"""Utilities for safely resolving evidence file paths.

.. deprecated::
    This module is a legacy re-export shim.  The canonical implementation now
    lives in :pymod:`core.paths`.  Import from there instead.
"""

from __future__ import annotations

from core.paths import resolve_within_root

__all__ = ["resolve_within_root"]
