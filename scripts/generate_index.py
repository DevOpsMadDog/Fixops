"""Generate repository inventory, import graph, and tree snapshot.

The original repository snapshot script only produced the inventory and
import graph that downstream tooling relied on.  For the broader analysis
workstream we also need a lightweight tree view so that the review package
can be consumed without needing access to the repository itself.

Running this script creates/updates the following artefacts under ``index/``:

``INVENTORY.csv``
    File level statistics including an inferred role.  Currently focused on
    Python modules because that is where the majority of the execution logic
    lives.

``graph.json``
    A simple import adjacency map that helps visualise coupling between
    modules.

``TREE.txt``
    Collapsed tree view of the repository (depth up to six levels) with noisy
    directories such as virtual environments removed so that reviewers can
    quickly understand the structure.

The script intentionally keeps the dependencies to the Python standard
library so that it can run inside constrained CI environments.
"""

from __future__ import annotations

import ast
import csv
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
INDEX_DIR = REPO_ROOT / "index"

# Default directories that contain executable Python code.  The caller can
# override this list via the FIXOPS_INDEX_TARGETS environment variable which
# expects a comma separated set of paths relative to the repository root.
DEFAULT_TARGET_DIRS = [
    "apps",
    "core",
    "enterprise",
    "prototypes",
    "scripts",
    "tests",
]
ENV_TARGETS = os.getenv("FIXOPS_INDEX_TARGETS")
if ENV_TARGETS:
    TARGET_DIRS: Sequence[str] = [
        segment.strip() for segment in ENV_TARGETS.split(",") if segment.strip()
    ]
else:
    TARGET_DIRS = DEFAULT_TARGET_DIRS

IGNORE_PREFIXES = {"tests/fixtures"}

ROLE_MAP = {
    "apps/api/app.py": "API",
    "apps/api/normalizers.py": "Parsing",
    "apps/api/pipeline.py": "Correlation",
    "core/configuration.py": "Config",
    "core/design_context_injector.py": "SSVC",
    "prototypes/decider/api.py": "Decision API",
}

TREE_MAX_DEPTH = 6
TREE_SKIP = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    "venv",
    ".venv",
    ".mypy_cache",
    ".pytest_cache",
    "data",
    "demo/data",
}


def iter_python_files() -> Iterable[Path]:
    for directory in TARGET_DIRS:
        base = REPO_ROOT / directory
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            rel = path.relative_to(REPO_ROOT).as_posix()
            if any(rel.startswith(prefix) for prefix in IGNORE_PREFIXES):
                continue
            yield path


def count_sloc(path: Path) -> int:
    sloc = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        sloc += 1
    return sloc


def detect_role(rel_path: str) -> str:
    return ROLE_MAP.get(rel_path, "Support")


def build_import_graph(files: Iterable[Path]) -> Dict[str, List[str]]:
    graph: Dict[str, List[str]] = defaultdict(list)
    module_map: Dict[str, str] = {}
    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        module = rel[:-3].replace("/", ".")  # strip .py
        module_map[module] = rel

    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        module = rel[:-3].replace("/", ".")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        targets: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    targets.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    targets.add(node.module)
        internal = [
            module_map[name]
            for name in targets
            if name in module_map and module_map[name] != rel
        ]
        graph[rel] = sorted(internal)
    return graph


def write_tree(root: Path, destination: Path, max_depth: int = TREE_MAX_DEPTH) -> None:
    """Write a compact tree representation to ``destination``.

    The implementation intentionally avoids relying on ``tree`` being
    available on the host system.  It mirrors the behaviour of ``tree -L``
    and skips a set of noisy directories defined in ``TREE_SKIP``.
    """

    def should_skip(path: Path) -> bool:
        name = path.name
        if name in TREE_SKIP:
            return True
        rel = path.relative_to(root).as_posix()
        return any(rel.startswith(prefix.rstrip("/") + "/") for prefix in TREE_SKIP)

    def walk(base: Path, depth: int, prefix: str, lines: List[str]) -> None:
        if depth > max_depth:
            return
        children = [
            p
            for p in sorted(base.iterdir(), key=lambda p: p.name)
            if not should_skip(p)
        ]
        for index, child in enumerate(children):
            connector = "└── " if index == len(children) - 1 else "├── "
            lines.append(f"{prefix}{connector}{child.name}")
            if child.is_dir() and depth < max_depth:
                extension = "    " if index == len(children) - 1 else "│   "
                walk(child, depth + 1, prefix + extension, lines)

    lines: List[str] = [root.name]
    walk(root, 1, "", lines)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    INDEX_DIR.mkdir(exist_ok=True)
    files = list(iter_python_files())

    inventory_rows: List[Tuple[str, int, str, str]] = []
    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        inventory_rows.append((rel, count_sloc(path), "Python", detect_role(rel)))

    inventory_rows.sort(key=lambda row: row[0])

    with (INDEX_DIR / "INVENTORY.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(["path", "sloc", "language", "role"])
        writer.writerows(inventory_rows)

    graph = build_import_graph(files)
    with (INDEX_DIR / "graph.json").open("w", encoding="utf-8") as handle:
        json.dump(graph, handle, indent=2, sort_keys=True)

    write_tree(REPO_ROOT, INDEX_DIR / "TREE.txt")


if __name__ == "__main__":
    main()
