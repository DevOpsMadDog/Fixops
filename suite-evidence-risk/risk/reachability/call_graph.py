"""Call graph construction for reachability analysis.

Supports Python (AST), JavaScript/TypeScript (regex-based static analysis),
Java (regex-based static analysis), and Go (regex-based static analysis).
All parsers are zero-dependency and work fully air-gapped.
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────
# Common helpers
# ────────────────────────────────────────────────────────
_IGNORE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        "vendor",
        "dist",
        "build",
        ".next",
        "target",
        "bin",
        "obj",
        ".gradle",
        "coverage",
        "test",
        "tests",
        "__tests__",
    }
)


def _should_skip(path: Path) -> bool:
    return any(part in _IGNORE_DIRS for part in path.parts)


def _node(
    file_path: str,
    line: int,
    *,
    is_public: bool = True,
    is_exported: bool = False,
    language: str = "python",
    kind: str = "function",
    annotations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create a new call-graph node."""
    return {
        "file": file_path,
        "line": line,
        "callers": [],
        "callees": [],
        "is_public": is_public,
        "is_exported": is_exported,
        "language": language,
        "kind": kind,  # function | method | class | handler | route
        "annotations": annotations or [],
    }


def _add_edge(
    graph: Dict[str, Any],
    caller: str,
    callee: str,
    file_path: str,
    line: int,
) -> None:
    """Add a directed edge caller→callee in the graph.

    Uses O(1) set-based dedup instead of O(N) list membership checks so that
    repeated edge additions during large-repo scans stay cheap.
    """
    if callee not in graph:
        graph[callee] = _node(file_path, line)
    if caller not in graph:
        graph[caller] = _node(file_path, line)

    # _callee_keys / _caller_keys are O(1) dedup sets kept in sync with the lists.
    caller_node = graph[caller]
    callee_node = graph[callee]

    if "_callee_keys" not in caller_node:
        caller_node["_callee_keys"] = {e["function"] for e in caller_node["callees"]}
    if callee not in caller_node["_callee_keys"]:
        caller_node["callees"].append({"function": callee, "file": file_path, "line": line})
        caller_node["_callee_keys"].add(callee)

    if "_caller_keys" not in callee_node:
        callee_node["_caller_keys"] = {e["function"] for e in callee_node["callers"]}
    if caller not in callee_node["_caller_keys"]:
        callee_node["callers"].append({"function": caller, "file": file_path, "line": line, "parent": None})
        callee_node["_caller_keys"].add(caller)


class CallGraphBuilder:
    """Build call graphs from source code for reachability analysis.

    Supports Python (ast), JavaScript/TypeScript (regex), Java (regex),
    and Go (regex).  All parsers are pure-Python / zero external dependency
    so they work air-gapped.
    """

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        self.config = config or {}
        self.max_depth = self.config.get("max_depth", 50)
        self.include_imports = self.config.get("include_imports", True)
        self.max_files = self.config.get("max_files", 5000)

    # ────────────────── public entry ──────────────────

    def build_call_graph(
        self,
        repo_path: Path,
        language_distribution: Optional[Dict[str, int]] = None,
    ) -> Dict[str, Any]:
        if language_distribution is None:
            language_distribution = {}

        call_graph: Dict[str, Any] = {}

        # Build for ALL detected languages (not just primary)
        builders = {
            "Python": self._build_python_call_graph,
            "JavaScript": self._build_javascript_call_graph,
            "TypeScript": self._build_javascript_call_graph,
            "Java": self._build_java_call_graph,
            "Go": self._build_go_call_graph,
        }

        if language_distribution:
            for lang in language_distribution:
                builder = builders.get(lang)
                if builder:
                    partial = builder(repo_path)
                    call_graph.update(partial)
        else:
            # Auto-detect: run every builder that finds matching files
            for lang, builder in builders.items():
                partial = builder(repo_path)
                if partial:
                    call_graph.update(partial)

        if not call_graph:
            call_graph = self._build_generic_call_graph(repo_path)

        return call_graph

    # ────────────────── Python (AST) ──────────────────

    def _build_python_call_graph(self, repo_path: Path) -> Dict[str, Any]:
        call_graph: Dict[str, Any] = {}
        python_files = [f for f in repo_path.rglob("*.py") if not _should_skip(f)]
        python_files = python_files[: self.max_files]

        for py_file in python_files:
            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content, filename=str(py_file))
                visitor = PythonCallGraphVisitor(str(py_file), call_graph)
                visitor.visit(tree)
            except (OSError, SyntaxError, ValueError) as e:
                logger.debug("Failed to parse %s: %s", py_file, e)

        return call_graph

    # ────────────────── JavaScript / TypeScript ──────────────────

    # Regex patterns for JS/TS static analysis
    _JS_FUNC_DEF = re.compile(
        r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(", re.MULTILINE
    )
    _JS_ARROW = re.compile(
        r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?[^)]*\)?\s*=>",
        re.MULTILINE,
    )
    _JS_METHOD = re.compile(
        r"(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{", re.MULTILINE
    )
    _JS_CLASS = re.compile(r"class\s+(\w+)", re.MULTILINE)
    _JS_CALL = re.compile(r"(?<!\w)(\w+)\s*\(", re.MULTILINE)
    _JS_IMPORT = re.compile(
        r"import\s+\{?\s*([^}]+?)\s*\}?\s+from\s+['\"]([^'\"]+)['\"]",
        re.MULTILINE,
    )
    _JS_REQUIRE = re.compile(
        r"(?:const|let|var)\s+(?:\{?\s*([^}]+?)\s*\}?)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
        re.MULTILINE,
    )
    _JS_EXPORT = re.compile(
        r"(?:module\.exports\s*=|export\s+(?:default\s+)?(?:function|class|const|let|var)\s+)(\w+)?",
        re.MULTILINE,
    )
    # Express/Koa/Fastify route patterns
    _JS_ROUTE = re.compile(
        r"(?:app|router)\s*\.\s*(get|post|put|delete|patch|use|all)\s*\(\s*['\"]([^'\"]+)['\"]",
        re.MULTILINE | re.IGNORECASE,
    )

    def _build_javascript_call_graph(self, repo_path: Path) -> Dict[str, Any]:
        call_graph: Dict[str, Any] = {}
        js_files = [
            f
            for f in repo_path.rglob("*")
            if f.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
            and not _should_skip(f)
        ]
        js_files = js_files[: self.max_files]

        if not js_files:
            return call_graph

        logger.info(
            "Building JavaScript/TypeScript call graph from %d files", len(js_files)
        )

        exports_by_module: Dict[str, Set[str]] = {}
        imports_map: Dict[str, List[Tuple[str, str]]] = {}  # file → [(name, module)]

        for js_file in js_files:
            try:
                content = js_file.read_text(encoding="utf-8", errors="replace")
                rel = str(js_file.relative_to(repo_path))
                self._parse_js_file(content, rel, call_graph, exports_by_module, imports_map)
            except OSError as e:
                logger.debug("Failed to read %s: %s", js_file, e)

        # Second pass: resolve cross-module edges via import→export matching
        self._resolve_js_imports(call_graph, exports_by_module, imports_map)

        return call_graph

    def _parse_js_file(
        self,
        content: str,
        file_path: str,
        graph: Dict[str, Any],
        exports_by_module: Dict[str, Set[str]],
        imports_map: Dict[str, List[Tuple[str, str]]],
    ) -> None:
        lines = content.split("\n")
        current_func: Optional[str] = None
        current_class: Optional[str] = None

        # Collect function/class definitions
        for match in self._JS_FUNC_DEF.finditer(content):
            name = match.group(1)
            line = content[: match.start()].count("\n") + 1
            fq = f"{current_class}.{name}" if current_class else name
            if fq not in graph:
                graph[fq] = _node(file_path, line, language="javascript", kind="function")
            exported = "export" in content[max(0, match.start() - 20) : match.start()]
            if exported:
                graph[fq]["is_exported"] = True

        for match in self._JS_ARROW.finditer(content):
            name = match.group(1)
            line = content[: match.start()].count("\n") + 1
            if name not in graph:
                graph[name] = _node(file_path, line, language="javascript", kind="function")
            exported = "export" in content[max(0, match.start() - 20) : match.start()]
            if exported:
                graph[name]["is_exported"] = True

        for match in self._JS_CLASS.finditer(content):
            name = match.group(1)
            line = content[: match.start()].count("\n") + 1
            if name not in graph:
                graph[name] = _node(file_path, line, language="javascript", kind="class")

        # Collect route registrations (these are entry points)
        for match in self._JS_ROUTE.finditer(content):
            method = match.group(1).upper()
            route_path = match.group(2)
            route_name = f"ROUTE:{method}:{route_path}"
            line = content[: match.start()].count("\n") + 1
            if route_name not in graph:
                graph[route_name] = _node(
                    file_path, line, language="javascript", kind="route",
                    is_exported=True, is_public=True,
                )
            # Link route to handler (the next function-like arg)
            after = content[match.end() :]
            handler_match = re.search(r"(\w+)", after)
            if handler_match:
                handler = handler_match.group(1)
                _add_edge(graph, route_name, handler, file_path, line)

        # Collect imports
        for match in self._JS_IMPORT.finditer(content):
            names = [n.strip().split(" as ")[0].strip() for n in match.group(1).split(",")]
            module = match.group(2)
            for n in names:
                if n:
                    imports_map.setdefault(file_path, []).append((n, module))

        for match in self._JS_REQUIRE.finditer(content):
            names = [n.strip() for n in match.group(1).split(",")]
            module = match.group(2)
            for n in names:
                if n:
                    imports_map.setdefault(file_path, []).append((n, module))

        # Collect exports
        for match in self._JS_EXPORT.finditer(content):
            name = match.group(1)
            if name:
                module_key = file_path.rsplit(".", 1)[0]
                exports_by_module.setdefault(module_key, set()).add(name)

        # Build call edges: scan function bodies for calls
        # Track line-level function scope
        func_defs: List[Tuple[str, int, int]] = []
        for match in self._JS_FUNC_DEF.finditer(content):
            name = match.group(1)
            start_line = content[: match.start()].count("\n") + 1
            func_defs.append((name, match.start(), match.end()))
        for match in self._JS_ARROW.finditer(content):
            name = match.group(1)
            func_defs.append((name, match.start(), match.end()))

        # For each function body, find calls
        for func_name, start_pos, _ in func_defs:
            # Find the end of the function body (brace matching)
            body_start = content.find("{", start_pos)
            if body_start == -1:
                # Arrow without braces — single expression
                body_end = content.find("\n", start_pos)
                if body_end == -1:
                    body_end = len(content)
            else:
                body_end = self._find_brace_end(content, body_start)  
            body = content[start_pos:body_end]
            for call_match in self._JS_CALL.finditer(body):
                called = call_match.group(1)
                if called in (
                    "if", "for", "while", "switch", "catch", "return",
                    "const", "let", "var", "new", "typeof", "import",
                    "require", "console", "setTimeout", "setInterval",
                    "Promise", "async", "await",
                ):
                    continue
                line = content[: start_pos + call_match.start()].count("\n") + 1
                _add_edge(graph, func_name, called, file_path, line)

    @staticmethod
    def _find_brace_end(content: str, start: int) -> int:
        depth = 0
        for i in range(start, min(len(content), start + 50000)):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        return min(len(content), start + 5000)

    def _resolve_js_imports(
        self,
        graph: Dict[str, Any],
        exports_by_module: Dict[str, Set[str]],
        imports_map: Dict[str, List[Tuple[str, str]]],
    ) -> None:
        for file_path, imports in imports_map.items():
            for name, module in imports:
                # Mark imported names as cross-module references
                if name in graph:
                    graph[name]["is_exported"] = True
                    graph[name].setdefault("imported_by", [])
                    if file_path not in graph[name]["imported_by"]:
                        graph[name]["imported_by"].append(file_path)

    # ────────────────── Java ──────────────────

    _JAVA_CLASS = re.compile(
        r"(?:public\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)", re.MULTILINE
    )
    _JAVA_INTERFACE = re.compile(r"interface\s+(\w+)", re.MULTILINE)
    _JAVA_METHOD = re.compile(
        r"(?:public|protected|private|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{",
        re.MULTILINE,
    )
    _JAVA_CALL = re.compile(r"(?<!\w)(\w+)\s*\(", re.MULTILINE)
    _JAVA_ANNOTATION = re.compile(r"@(\w+)(?:\(([^)]*)\))?", re.MULTILINE)
    _JAVA_IMPORT = re.compile(r"import\s+([\w.]+);", re.MULTILINE)
    # Spring / JAX-RS route annotations
    _JAVA_ROUTE = re.compile(
        r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
        re.MULTILINE,
    )

    def _build_java_call_graph(self, repo_path: Path) -> Dict[str, Any]:
        call_graph: Dict[str, Any] = {}
        java_files = [f for f in repo_path.rglob("*.java") if not _should_skip(f)]
        java_files = java_files[: self.max_files]

        if not java_files:
            return call_graph

        logger.info("Building Java call graph from %d files", len(java_files))

        for java_file in java_files:
            try:
                content = java_file.read_text(encoding="utf-8", errors="replace")
                rel = str(java_file.relative_to(repo_path))
                self._parse_java_file(content, rel, call_graph)
            except OSError as e:
                logger.debug("Failed to read %s: %s", java_file, e)

        return call_graph

    def _parse_java_file(
        self, content: str, file_path: str, graph: Dict[str, Any]
    ) -> None:
        # Find classes
        current_class: Optional[str] = None
        for match in self._JAVA_CLASS.finditer(content):
            current_class = match.group(1)
            line = content[: match.start()].count("\n") + 1
            if current_class not in graph:
                graph[current_class] = _node(
                    file_path, line, language="java", kind="class",
                    is_public="public" in content[max(0, match.start() - 30) : match.start()],
                )

        # Find annotations above methods
        annotation_positions: Dict[int, List[str]] = {}
        for match in self._JAVA_ANNOTATION.finditer(content):
            line = content[: match.start()].count("\n") + 1
            annotation_positions.setdefault(line, []).append(match.group(1))

        # Find methods
        method_defs: List[Tuple[str, int, int]] = []
        for match in self._JAVA_METHOD.finditer(content):
            method_name = match.group(1)
            line = content[: match.start()].count("\n") + 1
            fq = f"{current_class}.{method_name}" if current_class else method_name

            # Collect annotations from preceding lines
            method_annotations: List[str] = []
            for aline in range(max(1, line - 5), line):
                if aline in annotation_positions:
                    method_annotations.extend(annotation_positions[aline])

            is_handler = any(
                a in method_annotations
                for a in (
                    "GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
                    "PatchMapping", "RequestMapping", "GET", "POST", "PUT", "DELETE",
                    "Endpoint", "Controller", "RestController",
                )
            )

            if fq not in graph:
                graph[fq] = _node(
                    file_path, line, language="java",
                    kind="handler" if is_handler else "method",
                    is_public="public" in content[max(0, match.start() - 30) : match.start()],
                    is_exported=is_handler,
                    annotations=method_annotations,
                )

            method_defs.append((fq, match.start(), match.end()))

        # Route annotations → entry-point nodes
        for match in self._JAVA_ROUTE.finditer(content):
            route_path = match.group(1)
            annotation = content[match.start() : match.end()]
            method = "GET"
            for m in ("Post", "Put", "Delete", "Patch"):
                if m in annotation:
                    method = m.upper()
                    break
            route_name = f"ROUTE:{method}:{route_path}"
            line = content[: match.start()].count("\n") + 1
            if route_name not in graph:
                graph[route_name] = _node(
                    file_path, line, language="java", kind="route",
                    is_exported=True, is_public=True,
                )
            # Link to next method
            after = content[match.end() :]
            next_method = self._JAVA_METHOD.search(after)
            if next_method:
                nm = next_method.group(1)
                fq = f"{current_class}.{nm}" if current_class else nm
                _add_edge(graph, route_name, fq, file_path, line)

        # Build call edges within method bodies
        for func_name, start_pos, body_start in method_defs:
            brace = content.find("{", body_start - 1)
            if brace == -1:
                continue
            body_end = self._find_brace_end(content, brace)
            body = content[brace:body_end]
            for call_match in self._JAVA_CALL.finditer(body):
                called = call_match.group(1)
                if called in (
                    "if", "for", "while", "switch", "catch", "return",
                    "new", "throw", "try", "class", "void", "int",
                    "String", "boolean", "long", "double", "float",
                    "List", "Map", "Set", "Optional", "super", "this",
                ):
                    continue
                line = content[: brace + call_match.start()].count("\n") + 1
                called_fq = f"{current_class}.{called}" if current_class and f"{current_class}.{called}" in graph else called
                _add_edge(graph, func_name, called_fq, file_path, line)

    # ────────────────── Go ──────────────────

    _GO_FUNC = re.compile(r"func\s+(\w+)\s*\(", re.MULTILINE)
    _GO_METHOD = re.compile(r"func\s+\(\s*\w+\s+\*?(\w+)\s*\)\s+(\w+)\s*\(", re.MULTILINE)
    _GO_CALL = re.compile(r"(?<!\w)(\w+)\s*\(", re.MULTILINE)
    _GO_IMPORT = re.compile(r'"([\w./\-]+)"', re.MULTILINE)
    _GO_STRUCT = re.compile(r"type\s+(\w+)\s+struct\s*\{", re.MULTILINE)
    _GO_INTERFACE = re.compile(r"type\s+(\w+)\s+interface\s*\{", re.MULTILINE)
    # net/http, Gin, Echo, Fiber route patterns
    _GO_ROUTE = re.compile(
        r'(?:'
        r'(?:http\.)?(?:Handle|HandleFunc)'  # net/http
        r'|(?:r|e|app|g|router|mux)\s*\.\s*(?:GET|POST|PUT|DELETE|PATCH|Handle|HandleFunc|Group)'  # frameworks
        r')\s*\(\s*"([^"]+)"',
        re.MULTILINE,
    )

    def _build_go_call_graph(self, repo_path: Path) -> Dict[str, Any]:
        call_graph: Dict[str, Any] = {}
        go_files = [f for f in repo_path.rglob("*.go") if not _should_skip(f)]
        go_files = go_files[: self.max_files]

        if not go_files:
            return call_graph

        logger.info("Building Go call graph from %d files", len(go_files))

        for go_file in go_files:
            try:
                content = go_file.read_text(encoding="utf-8", errors="replace")
                rel = str(go_file.relative_to(repo_path))
                self._parse_go_file(content, rel, call_graph)
            except OSError as e:
                logger.debug("Failed to read %s: %s", go_file, e)

        return call_graph

    def _parse_go_file(
        self, content: str, file_path: str, graph: Dict[str, Any]
    ) -> None:
        # Package-level functions
        func_defs: List[Tuple[str, int, int]] = []
        for match in self._GO_FUNC.finditer(content):
            name = match.group(1)
            line = content[: match.start()].count("\n") + 1
            is_exported = name[0].isupper() if name else False
            if name not in graph:
                graph[name] = _node(
                    file_path, line, language="go", kind="function",
                    is_public=is_exported, is_exported=is_exported,
                )
            func_defs.append((name, match.start(), match.end()))

        # Method definitions (receiver type)
        for match in self._GO_METHOD.finditer(content):
            receiver = match.group(1)
            method_name = match.group(2)
            fq = f"{receiver}.{method_name}"
            line = content[: match.start()].count("\n") + 1
            is_exported = method_name[0].isupper() if method_name else False
            if fq not in graph:
                graph[fq] = _node(
                    file_path, line, language="go", kind="method",
                    is_public=is_exported, is_exported=is_exported,
                )
            func_defs.append((fq, match.start(), match.end()))

        # Structs
        for match in self._GO_STRUCT.finditer(content):
            name = match.group(1)
            line = content[: match.start()].count("\n") + 1
            if name not in graph:
                graph[name] = _node(file_path, line, language="go", kind="class")

        # Routes (HTTP entry points)
        for match in self._GO_ROUTE.finditer(content):
            route_path = match.group(1)
            line = content[: match.start()].count("\n") + 1
            full = content[max(0, match.start() - 10) : match.end()]
            method = "GET"
            for m in ("POST", "PUT", "DELETE", "PATCH"):
                if m in full.upper():
                    method = m
                    break
            route_name = f"ROUTE:{method}:{route_path}"
            if route_name not in graph:
                graph[route_name] = _node(
                    file_path, line, language="go", kind="route",
                    is_exported=True, is_public=True,
                )
            # Link to handler (next identifier after the route string)
            after = content[match.end() :]
            handler_match = re.search(r",\s*(\w+)", after)
            if handler_match:
                handler = handler_match.group(1)
                _add_edge(graph, route_name, handler, file_path, line)

        # Build call edges within function bodies
        for func_name, start_pos, header_end in func_defs:
            brace = content.find("{", header_end - 1)
            if brace == -1:
                continue
            body_end = self._find_brace_end(content, brace)
            body = content[brace:body_end]
            for call_match in self._GO_CALL.finditer(body):
                called = call_match.group(1)
                if called in (
                    "if", "for", "range", "switch", "case", "return",
                    "go", "defer", "select", "make", "len", "cap",
                    "append", "copy", "delete", "close", "panic",
                    "recover", "new", "print", "println", "nil",
                    "true", "false", "string", "int", "bool", "byte",
                    "error", "func", "var", "const", "type", "map",
                ):
                    continue
                line = content[: brace + call_match.start()].count("\n") + 1
                _add_edge(graph, func_name, called, file_path, line)

    # ────────────────── Generic fallback ──────────────────

    _GENERIC_FUNC = re.compile(r"(?:def|func|function|fn|sub|proc)\s+(\w+)", re.MULTILINE)

    def _build_generic_call_graph(self, repo_path: Path) -> Dict[str, Any]:
        """Fallback: heuristic regex for any language."""
        call_graph: Dict[str, Any] = {}
        code_exts = {".py", ".js", ".ts", ".java", ".go", ".rb", ".rs", ".c", ".cpp", ".cs", ".php"}
        files = [
            f for f in repo_path.rglob("*")
            if f.suffix in code_exts and not _should_skip(f)
        ][: self.max_files]

        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                rel = str(f.relative_to(repo_path))
                for match in self._GENERIC_FUNC.finditer(content):
                    name = match.group(1)
                    line = content[: match.start()].count("\n") + 1
                    if name not in call_graph:
                        call_graph[name] = _node(rel, line, language="unknown")
            except OSError:
                continue

        return call_graph

    # ────────────────── Query helpers ──────────────────

    @staticmethod
    def is_reachable_from_entry(
        graph: Dict[str, Any], target: str, max_depth: int = 50
    ) -> Tuple[bool, List[str]]:
        """Check if *target* is reachable from any entry point (route/handler/exported).

        Returns (reachable, call_chain).
        """
        entry_points = [
            name
            for name, node in graph.items()
            if node.get("kind") in ("route", "handler")
            or node.get("is_exported")
            or node.get("is_public")
        ]

        for ep in entry_points:
            found, chain = CallGraphBuilder._bfs(graph, ep, target, max_depth)
            if found:
                return True, chain

        return False, []

    @staticmethod
    def _bfs(
        graph: Dict[str, Any], start: str, target: str, max_depth: int
    ) -> Tuple[bool, List[str]]:
        from collections import deque

        visited: Set[str] = set()
        queue: deque[Tuple[str, List[str]]] = deque([(start, [start])])

        while queue:
            current, path = queue.popleft()
            if current == target:
                return True, path
            if current in visited or len(path) > max_depth:
                continue
            visited.add(current)
            node = graph.get(current)
            if not node:
                continue
            for callee in node.get("callees", []):
                callee_name = callee.get("function", "")
                if callee_name and callee_name not in visited:
                    queue.append((callee_name, path + [callee_name]))

        return False, []

    @staticmethod
    def get_entry_points(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return all entry points (routes, handlers, exported functions)."""
        results = []
        for name, node in graph.items():
            if node.get("kind") in ("route", "handler") or node.get("is_exported"):
                results.append({"name": name, **node})
        return results

    @staticmethod
    def get_graph_stats(graph: Dict[str, Any]) -> Dict[str, Any]:
        """Return summary statistics for the call graph."""
        languages: Dict[str, int] = {}
        kinds: Dict[str, int] = {}
        for node in graph.values():
            lang = node.get("language", "unknown")
            kind = node.get("kind", "unknown")
            languages[lang] = languages.get(lang, 0) + 1
            kinds[kind] = kinds.get(kind, 0) + 1

        total_edges = sum(len(n.get("callees", [])) for n in graph.values())
        entry_points = sum(
            1 for n in graph.values()
            if n.get("kind") in ("route", "handler") or n.get("is_exported")
        )

        return {
            "total_nodes": len(graph),
            "total_edges": total_edges,
            "entry_points": entry_points,
            "languages": languages,
            "kinds": kinds,
        }


class PythonCallGraphVisitor(ast.NodeVisitor):
    """AST visitor for building Python call graphs."""

    def __init__(self, file_path: str, call_graph: Dict[str, Any]):
        """Initialize visitor.

        Parameters
        ----------
        file_path
            Path to Python file being analyzed.
        call_graph
            Call graph dictionary to populate.
        """
        self.file_path = file_path
        self.call_graph = call_graph
        self.current_function: Optional[str] = None
        self.current_class: Optional[str] = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        func_name = node.name
        full_name = (
            f"{self.current_class}.{func_name}" if self.current_class else func_name
        )

        # Store function info
        if full_name not in self.call_graph:
            self.call_graph[full_name] = {
                "file": self.file_path,
                "line": node.lineno,
                "callers": [],
                "callees": [],
                "is_public": not func_name.startswith("_"),
                "is_exported": False,  # Would need to check __all__ or exports
            }

        # Track current function
        old_function = self.current_function
        self.current_function = full_name

        # Visit function body to find calls
        self.generic_visit(node)

        self.current_function = old_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definition."""
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function call."""
        if not self.current_function:
            return

        # Extract called function name
        if isinstance(node.func, ast.Name):
            called_func = node.func.id
        elif isinstance(node.func, ast.Attribute):
            called_func = node.func.attr
        else:
            return

        # Add to call graph
        if called_func not in self.call_graph:
            self.call_graph[called_func] = {
                "file": self.file_path,
                "line": node.lineno,
                "callers": [],
                "callees": [],
                "is_public": True,
                "is_exported": False,
            }

        # Add caller relationship — use O(1) set dedup instead of O(N) list search.
        callee_node = self.call_graph[called_func]
        if "_caller_keys" not in callee_node:
            callee_node["_caller_keys"] = {e["function"] for e in callee_node["callers"]}
        if self.current_function not in callee_node["_caller_keys"]:
            callee_node["callers"].append({
                "function": self.current_function,
                "file": self.file_path,
                "line": node.lineno,
                "parent": None,
            })
            callee_node["_caller_keys"].add(self.current_function)

        # Add callee relationship — same O(1) dedup.
        if self.current_function in self.call_graph:
            caller_node = self.call_graph[self.current_function]
            if "_callee_keys" not in caller_node:
                caller_node["_callee_keys"] = {e["function"] for e in caller_node["callees"]}
            if called_func not in caller_node["_callee_keys"]:
                caller_node["callees"].append({
                    "function": called_func,
                    "file": self.file_path,
                    "line": node.lineno,
                })
                caller_node["_callee_keys"].add(called_func)
