#!/usr/bin/env python3
"""Generate repository-wide code intelligence and duplication reports."""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
ENTERPRISE_SRC = REPO_ROOT / "fixops-enterprise"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if ENTERPRISE_SRC.exists() and str(ENTERPRISE_SRC) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_SRC))


@dataclass
class FunctionReport:
    name: str
    lineno: int
    end_lineno: int
    docstring: str | None
    complexity: int
    calls: List[str]


@dataclass
class ClassReport:
    name: str
    lineno: int
    end_lineno: int
    docstring: str | None
    methods: List[FunctionReport]


@dataclass
class ModuleReport:
    path: Path
    docstring: str | None
    imports: List[str]
    classes: List[ClassReport]
    functions: List[FunctionReport]


def iter_python_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        if "WIP" in path.parts:
            continue
        yield path


_COMPLEXITY_NODES: Tuple[type, ...] = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.With,
    ast.AsyncWith,
    ast.BoolOp,
    ast.IfExp,
    ast.ListComp,
    ast.DictComp,
    ast.SetComp,
    ast.GeneratorExp,
)


def cyclomatic_complexity(node: ast.AST) -> int:
    score = 1
    for child in ast.walk(node):
        if isinstance(child, _COMPLEXITY_NODES):
            score += 1
    return score


def collect_calls(node: ast.AST) -> List[str]:
    calls: List[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            target = child.func
            if isinstance(target, ast.Name):
                calls.append(target.id)
            elif isinstance(target, ast.Attribute):
                calls.append(target.attr)
    return sorted(set(calls))


def module_report(path: Path) -> ModuleReport:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    module_docstring = ast.get_docstring(tree)
    imports: List[str] = []
    classes: List[ClassReport] = []
    functions: List[FunctionReport] = []

    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            else:
                module = "" if node.module is None else node.module
                imports.append(module)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_doc = ast.get_docstring(node)
            func_report = FunctionReport(
                name=node.name,
                lineno=node.lineno,
                end_lineno=getattr(node, "end_lineno", node.lineno),
                docstring=func_doc,
                complexity=cyclomatic_complexity(node),
                calls=collect_calls(node),
            )
            functions.append(func_report)
        elif isinstance(node, ast.ClassDef):
            cls_doc = ast.get_docstring(node)
            methods: List[FunctionReport] = []
            for body_item in node.body:
                if isinstance(body_item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_doc = ast.get_docstring(body_item)
                    methods.append(
                        FunctionReport(
                            name=body_item.name,
                            lineno=body_item.lineno,
                            end_lineno=getattr(
                                body_item, "end_lineno", body_item.lineno
                            ),
                            docstring=method_doc,
                            complexity=cyclomatic_complexity(body_item),
                            calls=collect_calls(body_item),
                        )
                    )
            classes.append(
                ClassReport(
                    name=node.name,
                    lineno=node.lineno,
                    end_lineno=getattr(node, "end_lineno", node.lineno),
                    docstring=cls_doc,
                    methods=methods,
                )
            )

    return ModuleReport(
        path=path,
        docstring=module_docstring,
        imports=sorted(set(imports)),
        classes=classes,
        functions=functions,
    )


def serialise_module(report: ModuleReport) -> Dict[str, Any]:
    return {
        "docstring": report.docstring,
        "imports": report.imports,
        "classes": [
            {
                "name": cls.name,
                "lineno": cls.lineno,
                "end_lineno": cls.end_lineno,
                "docstring": cls.docstring,
                "methods": [
                    {
                        "name": method.name,
                        "lineno": method.lineno,
                        "end_lineno": method.end_lineno,
                        "docstring": method.docstring,
                        "cyclomatic_complexity": method.complexity,
                        "calls": method.calls,
                    }
                    for method in cls.methods
                ],
            }
            for cls in report.classes
        ],
        "functions": [
            {
                "name": func.name,
                "lineno": func.lineno,
                "end_lineno": func.end_lineno,
                "docstring": func.docstring,
                "cyclomatic_complexity": func.complexity,
                "calls": func.calls,
            }
            for func in report.functions
        ],
    }


def build_import_graph(reports: Sequence[ModuleReport]) -> Dict[str, Set[str]]:
    graph: Dict[str, Set[str]] = defaultdict(set)
    for report in reports:
        rel_path = report.path.relative_to(REPO_ROOT).as_posix()
        module_name = rel_path.replace("/", ".").rsplit(".py", 1)[0]
        for target in report.imports:
            if target:
                graph[module_name].add(target)
    return graph


def write_import_graph(graph: Mapping[str, Iterable[str]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = ["digraph imports {"]
    for source, targets in sorted(graph.items()):
        for target in sorted(set(targets)):
            lines.append(f'  "{source}" -> "{target}";')
    lines.append("}")
    (out_dir / "import_graph.dot").write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_callgraph(
    reports: Sequence[ModuleReport],
) -> Dict[str, List[Tuple[str, str]]]:
    grouped: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    for report in reports:
        rel_path = report.path.relative_to(REPO_ROOT)
        group = rel_path.parts[0]
        caller_prefix = rel_path.as_posix()
        for func in report.functions:
            caller = f"{caller_prefix}:{func.name}"
            for callee in func.calls:
                grouped[group].append((caller, callee))
        for cls in report.classes:
            for method in cls.methods:
                caller = f"{caller_prefix}:{cls.name}.{method.name}"
                for callee in method.calls:
                    grouped[group].append((caller, callee))
    return grouped


def write_callgraph(
    callgraph: Mapping[str, List[Tuple[str, str]]], out_dir: Path
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for group, edges in callgraph.items():
        path = out_dir / f"{group}.dot"
        lines = ["digraph callgraph {"]
        for source, target in edges:
            lines.append(f'  "{source}" -> "{target}";')
        lines.append("}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def detect_duplicates(reports: Sequence[ModuleReport]) -> Dict[str, Any]:
    by_name: Dict[str, List[str]] = defaultdict(list)
    by_hash: Dict[str, List[str]] = defaultdict(list)
    for report in reports:
        rel = report.path.relative_to(REPO_ROOT).as_posix()
        by_name[report.path.name].append(rel)
        source = report.path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        fingerprint = ast.dump(tree, include_attributes=False)
        by_hash[fingerprint].append(rel)
    duplicate_names = {name: paths for name, paths in by_name.items() if len(paths) > 1}
    duplicate_hashes = {
        f"group_{index}": paths
        for index, (fingerprint, paths) in enumerate(by_hash.items(), start=1)
        if len(paths) > 1
    }
    return {"duplicate_filenames": duplicate_names, "duplicate_asts": duplicate_hashes}


def stage_runner_overview() -> Dict[str, Any]:
    from core.stage_runner import StageRunner

    outputs = dict(StageRunner._OUTPUT_FILENAMES)
    inputs = dict(StageRunner._INPUT_FILENAMES)
    stages = []
    for stage, output in outputs.items():
        method = f"_process_{stage}"
        stages.append(
            {
                "stage": stage,
                "input_hint": inputs.get(stage),
                "processor": method,
                "output": output,
            }
        )
    return {
        "stages": stages,
        "risk_rules": len(getattr(StageRunner, "_RISK_RULES", {})),
    }


def detect_gaps(stage_runner_path: Path) -> Dict[str, Any]:
    expected_outputs = {
        "requirements.json",
        "design.manifest.json",
        "build.report.json",
        "test.report.json",
        "deploy.manifest.json",
        "operate.snapshot.json",
        "decision.json",
    }
    source = stage_runner_path.read_text(encoding="utf-8")
    from core.stage_runner import StageRunner

    actual_outputs = set(StageRunner._OUTPUT_FILENAMES.values())
    missing_outputs = sorted(expected_outputs - actual_outputs)
    signing_present = "sign_manifest" in source
    registry_present = "RunRegistry" in source or "self.registry" in source
    transparency_present = "transparency.index" in source
    return {
        "missing_canonical_outputs": missing_outputs,
        "signing_logic_present": signing_present,
        "run_registry_usage": registry_present,
        "transparency_index": transparency_present,
    }


def write_json(payload: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate FixOps deep review artefacts"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "reports" / "deep_review",
        help="Output directory",
    )
    args = parser.parse_args(argv)

    out_dir: Path = args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    reports: List[ModuleReport] = []
    for path in iter_python_files(REPO_ROOT):
        try:
            reports.append(module_report(path))
        except SyntaxError as exc:
            print(f"Skipping {path}: {exc}")

    index_payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "files": {
            report.path.relative_to(REPO_ROOT).as_posix(): serialise_module(report)
            for report in reports
        },
    }
    write_json(index_payload, out_dir / "codewalk" / "index.json")

    import_graph = build_import_graph(reports)
    write_import_graph(import_graph, out_dir / "graphs")

    callgraph = build_callgraph(reports)
    write_callgraph(callgraph, out_dir / "callgraph")

    duplicates = detect_duplicates(reports)
    write_json(duplicates, out_dir / "duplicates" / "index.json")

    cli_flow = stage_runner_overview()
    write_json(cli_flow, out_dir / "cli_flow.json")

    gaps = detect_gaps(REPO_ROOT / "core" / "stage_runner.py")
    write_json(gaps, out_dir / "gaps.json")

    print(f"Deep review artefacts written to {out_dir}")
    return 0


if __name__ == "__main__":  # pragma: no cover - manual execution
    raise SystemExit(main())
