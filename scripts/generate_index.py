"""Generate inventory and import graph for core FixOps modules."""
from __future__ import annotations

import ast
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
INDEX_DIR = REPO_ROOT / "index"
TARGET_DIRS = ["backend", "fixops", "new_backend", "tests"]
IGNORE_PREFIXES = {"tests/fixtures"}

ROLE_MAP = {
    "backend/app.py": "API",
    "backend/normalizers.py": "Parsing",
    "backend/pipeline.py": "Correlation",
    "fixops/configuration.py": "Config",
    "fixops/design_context_injector.py": "SSVC",
    "new_backend/api.py": "Decision API",
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


def main() -> None:
    INDEX_DIR.mkdir(exist_ok=True)
    files = list(iter_python_files())

    inventory_rows: List[Tuple[str, int, str, str]] = []
    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        inventory_rows.append((rel, count_sloc(path), "Python", detect_role(rel)))

    inventory_rows.sort(key=lambda row: row[0])

    with (INDEX_DIR / "INVENTORY.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["path", "sloc", "language", "role"])
        writer.writerows(inventory_rows)

    graph = build_import_graph(files)
    with (INDEX_DIR / "graph.json").open("w", encoding="utf-8") as handle:
        json.dump(graph, handle, indent=2, sort_keys=True)


if __name__ == "__main__":
    main()
