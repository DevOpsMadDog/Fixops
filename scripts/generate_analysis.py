"""Produce lightweight analysis artefacts for the FixOps repository.

The goal of this module is not to replace full security reviews but to
collect reproducible evidence that supports the accompanying documentation.

Outputs
=======

``analysis/FILE_SUMMARIES.csv``
    High level per-file metadata covering the inferred role, top-level
    symbols, external imports and heuristic risk flags.

``analysis/DATA_CONTROL_FLOWS.md``
    Markdown narrative that explains how data moves through the platform.
    The file combines static templates with extracted interface details so
    reviewers can trace the paths cited in the main report.

``analysis/TRACEABILITY.csv``
    Traceability matrix that connects platform capabilities with the
    underlying source files.

The script only relies on the Python standard library to keep the execution
environment simple.
"""

from __future__ import annotations

import ast
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
ANALYSIS_DIR = REPO_ROOT / "analysis"

DEFAULT_TARGET_DIRS = [
    "apps",
    "core",
    "enterprise",
    "prototypes",
    "scripts",
    "tests",
]


def iter_python_files(target_dirs: Sequence[str]) -> Iterable[Path]:
    for directory in target_dirs:
        base = REPO_ROOT / directory
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            yield path


@dataclass
class ModuleSummary:
    path: str
    role: str
    symbols: str
    external_calls: str
    risks: str
    flags: str


def load_module_map(files: Iterable[Path]) -> Dict[str, str]:
    module_map: Dict[str, str] = {}
    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        module_map[rel[:-3].replace("/", ".")] = rel
    return module_map


def infer_role(rel_path: str) -> str:
    if rel_path.startswith("apps/api"):
        return "API"
    if rel_path.startswith("core/"):
        return "Core Logic"
    if rel_path.startswith("enterprise/"):
        return "Enterprise Overlay"
    if rel_path.startswith("prototypes/decider/"):
        return "Prototype"
    if rel_path.startswith("tests/"):
        return "Tests"
    if rel_path.startswith("scripts/"):
        return "Tooling"
    return "Support"


def extract_symbols(tree: ast.AST) -> List[str]:
    symbols: List[str] = []
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, ast.FunctionDef):
            symbols.append(node.name)
        elif isinstance(node, ast.AsyncFunctionDef):
            symbols.append(node.name)
        elif isinstance(node, ast.ClassDef):
            symbols.append(node.name)
    return symbols


def collect_external_imports(tree: ast.AST, module_map: Dict[str, str]) -> List[str]:
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    external = sorted(name for name in imports if all(not key.startswith(name) for key in module_map))
    return external


def detect_risks(tree: ast.AST, source: str) -> List[str]:
    risks: set[str] = set()
    if "eval(" in source or "exec(" in source:
        risks.add("dynamic-execution")
    if "subprocess" in source:
        risks.add("subprocess-usage")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            risks.add("file-io")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            risks.add("bare-except")
    return sorted(risks)


def detect_flags(source: str) -> List[str]:
    flags: set[str] = set()
    if "TODO" in source or "FIXME" in source:
        flags.add("TODO")
    if "pass\n" in source:
        flags.add("STUB")
    if "raise NotImplementedError" in source:
        flags.add("NOT_IMPLEMENTED")
    return sorted(flags)


def summarise_files(target_dirs: Sequence[str]) -> List[ModuleSummary]:
    files = list(iter_python_files(target_dirs))
    module_map = load_module_map(files)
    summaries: List[ModuleSummary] = []
    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        summaries.append(
            ModuleSummary(
                path=rel,
                role=infer_role(rel),
                symbols=", ".join(extract_symbols(tree)) or "(module-level)",
                external_calls=", ".join(collect_external_imports(tree, module_map)) or "(internal)",
                risks=", ".join(detect_risks(tree, source)) or "none",
                flags=", ".join(detect_flags(source)) or "none",
            )
        )
    summaries.sort(key=lambda item: item.path)
    return summaries


def write_file_summaries(summaries: Sequence[ModuleSummary]) -> None:
    ANALYSIS_DIR.mkdir(exist_ok=True)
    with (ANALYSIS_DIR / "FILE_SUMMARIES.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["path", "role", "key symbols", "external calls", "risks", "flags"])
        for summary in summaries:
            writer.writerow([
                summary.path,
                summary.role,
                summary.symbols,
                summary.external_calls,
                summary.risks,
                summary.flags,
            ])


def write_data_control_flows(summaries: Sequence[ModuleSummary]) -> None:
    inbound = [item.path for item in summaries if item.role in {"API", "Prototype"}]
    persistence = [
        item.path
        for item in summaries
        if "database" in item.path or "storage" in item.path or "models" in item.path
    ]
    with (ANALYSIS_DIR / "DATA_CONTROL_FLOWS.md").open("w", encoding="utf-8") as handle:
        handle.write("# Data & Control Flows\n\n")
        handle.write("This document is generated automatically from the source tree.\n\n")
        handle.write("## Inbound Interfaces\n\n")
        for path in inbound:
            handle.write(f"- `{path}`\n")
        handle.write("\n## Persistence Layers\n\n")
        if persistence:
            for path in persistence:
                handle.write(f"- `{path}`\n")
        else:
            handle.write("- UNKNOWN\n")
        handle.write("\n## Configuration & Secrets\n\n")
        config_files = [item.path for item in summaries if "config" in item.path or "settings" in item.path]
        if config_files:
            for path in config_files:
                handle.write(f"- `{path}`\n")
        else:
            handle.write("- UNKNOWN\n")
        handle.write("\n## Error Handling & Retry Semantics\n\n")
        handle.write("- See individual modules listed in `FILE_SUMMARIES.csv` for TODO markers.\n")


def write_traceability_matrix(summaries: Sequence[ModuleSummary]) -> None:
    trace_rows: List[Tuple[str, str, str]] = []
    capability_map = {
        "API ingestion": ["apps/api/app.py", "apps/api/pipeline.py"],
        "Exploit intelligence": ["core/exploit_signals.py"],
        "Compliance overlays": ["apps/api/pipeline.py", "core/compliance.py"],
        "SSVC scoring": ["core/design_context_injector.py"],
        "Prototype decider": ["prototypes/decider/api.py"],
    }
    for capability, files in capability_map.items():
        for file in files:
            trace_rows.append((capability, file, "UNKNOWN"))

    with (ANALYSIS_DIR / "TRACEABILITY.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["capability", "file", "status"])
        for capability, file, status in trace_rows:
            writer.writerow([capability, file, status])


def main(target_dirs: Sequence[str] | None = None) -> None:
    dirs = list(target_dirs or DEFAULT_TARGET_DIRS)
    summaries = summarise_files(dirs)
    write_file_summaries(summaries)
    write_data_control_flows(summaries)
    write_traceability_matrix(summaries)


if __name__ == "__main__":
    main()
