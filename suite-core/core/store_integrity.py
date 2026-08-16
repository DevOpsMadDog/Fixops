"""Detect databases that exist in more than one place.

A relative SQLite path resolves against the working directory, so the same logical store
can land in two files depending on how the process was started — and neither copy knows
about the other. Measured in the running container on 2026-08-16: **49 database names at
two locations, 13 with genuinely diverged data**, including deduplication clusters at
5,898 rows in one copy and 0 in the other, and TrustGraph at 250 against 38.

Nothing surfaced it. The application read one copy, wrote one copy, and reported success;
the other simply aged. For a product sold on evidence, silently splitting a customer's
data is disqualifying — an audit trail with half its rows in a file nobody opens is worse
than no audit trail, because it looks complete.

ADR-006 anchors the data directory so new writes converge, and a lint gate stops the
pattern spreading. This closes the loop at runtime: if a deployment *already* has split
stores, say so at startup instead of leaving it to be discovered by a customer.

The check **warns** rather than refusing to boot. Existing deployments have accumulated
splits that an operator cannot resolve during a restart, and taking a running system down
to report a pre-existing condition would do more damage than the condition. Set
``FIXOPS_STRICT_STORES=1`` to make it fatal — appropriate for a fresh install or CI,
where a split store means a configuration error rather than history.
"""

from __future__ import annotations

import collections
import logging
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

__all__ = ["SplitStoreError", "find_split_stores", "check_store_integrity"]

_IGNORED_PARTS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "site-packages"}


class SplitStoreError(RuntimeError):
    """The same database name exists at more than one location."""


def find_split_stores(
    root: Path, *, ignore: Optional[Iterable[str]] = None
) -> Dict[str, List[Path]]:
    """Return database basenames that appear at more than one path under ``root``.

    Args:
        root: Directory to search.
        ignore: Basenames to exclude (e.g. per-tenant databases that are *expected*
            to repeat across tenant directories).

    Returns:
        ``{basename: [paths]}`` for every name found more than once, sorted by name.
    """
    skip = set(ignore or ())
    seen: Dict[str, List[Path]] = collections.defaultdict(list)

    for path in root.rglob("*.db"):
        if set(path.parts) & _IGNORED_PARTS:
            continue
        if path.name in skip:
            continue
        seen[path.name].append(path)

    return {
        name: sorted(paths)
        for name, paths in sorted(seen.items())
        if len(paths) > 1
    }


def check_store_integrity(root: Optional[Path] = None) -> Dict[str, List[Path]]:
    """Report split stores at startup; raise only when strictness is requested.

    Args:
        root: Directory to search. Defaults to the anchored data directory's parent, so
            both ``data/`` and ``.fixops_data/`` are covered.

    Returns:
        The mapping from :func:`find_split_stores`, empty when the deployment is clean.

    Raises:
        SplitStoreError: Splits were found and ``FIXOPS_STRICT_STORES`` is set.
    """
    if root is None:
        data_dir = os.environ.get("FIXOPS_DATA_DIR")
        root = Path(data_dir).parent if data_dir else Path.cwd()

    try:
        splits = find_split_stores(Path(root))
    except OSError as exc:  # unreadable tree must not stop startup
        logger.debug("store integrity scan skipped: %s", exc)
        return {}

    if not splits:
        logger.debug("store integrity: no duplicated database names under %s", root)
        return {}

    detail = "; ".join(
        f"{name} @ {', '.join(str(p.parent) for p in paths)}"
        for name, paths in list(splits.items())[:8]
    )
    message = (
        f"store integrity: {len(splits)} database name(s) exist at more than one "
        f"location under {root}. The application reads one copy and writes one copy; "
        f"the others age silently and their contents will never appear in the product. "
        f"First offenders: {detail}"
    )

    if os.environ.get("FIXOPS_STRICT_STORES", "").strip().lower() in ("1", "true", "yes"):
        raise SplitStoreError(message)

    logger.warning("%s (set FIXOPS_STRICT_STORES=1 to make this fatal)", message)
    return splits
