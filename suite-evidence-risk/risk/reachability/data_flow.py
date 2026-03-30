"""Data flow analysis for exploitability verification.

Performs taint tracking from user-controlled sources to dangerous sinks
across Python, JavaScript/TypeScript, Java, and Go codebases.
Zero external dependencies — works fully air-gapped.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────
# Taint source / sink / sanitizer catalogs (per language)
# ────────────────────────────────────────────────────────

# Sources: where user-controlled data enters the application
_SOURCES: Dict[str, FrozenSet[str]] = {
    "python": frozenset({
        "request.args", "request.form", "request.json", "request.data",
        "request.files", "request.headers", "request.cookies",
        "request.query_params", "request.body", "request.path_params",
        "input", "sys.stdin", "os.environ", "getenv",
        "flask.request", "django.request", "starlette.request",
    }),
    "javascript": frozenset({
        "req.body", "req.params", "req.query", "req.headers", "req.cookies",
        "req.url", "req.path", "req.hostname",
        "document.location", "window.location", "location.href",
        "document.URL", "document.referrer",
        "document.cookie", "localStorage", "sessionStorage",
        "process.env", "readline", "fs.readFileSync",
        "event.target.value", "FormData",
    }),
    "java": frozenset({
        "request.getParameter", "request.getHeader", "request.getCookies",
        "request.getInputStream", "request.getReader",
        "request.getQueryString", "request.getRequestURI",
        "request.getPathInfo", "request.getServletPath",
        "System.getenv", "Scanner", "BufferedReader",
        "HttpServletRequest", "@RequestParam", "@PathVariable",
        "@RequestBody", "@RequestHeader", "@CookieValue",
    }),
    "go": frozenset({
        "r.URL.Query", "r.FormValue", "r.PostFormValue",
        "r.Header.Get", "r.Body", "r.URL.Path",
        "r.Cookie", "r.MultipartForm",
        "os.Getenv", "os.Args", "flag.String",
        "bufio.Scanner", "ioutil.ReadAll", "io.ReadAll",
        "c.Query", "c.Param", "c.PostForm",  # Gin
        "c.FormValue", "c.QueryParam",  # Echo
    }),
}

# Sinks: dangerous operations where tainted data causes vulnerabilities
_SINKS: Dict[str, Dict[str, FrozenSet[str]]] = {
    "sql_injection": {
        "python": frozenset({
            "execute", "executemany", "raw", "cursor.execute",
            "text", "engine.execute", "session.execute",
            "db.execute", "conn.execute",
        }),
        "javascript": frozenset({
            "query", "raw", "exec", "prepare",
            "sequelize.query", "knex.raw", "pool.query",
            "connection.query", "db.query", "mongoose.exec",
        }),
        "java": frozenset({
            "executeQuery", "executeUpdate", "execute",
            "prepareStatement", "createQuery", "createNativeQuery",
            "nativeQuery", "jdbcTemplate.query",
            "jdbcTemplate.update", "NamedParameterJdbcTemplate",
        }),
        "go": frozenset({
            "db.Query", "db.QueryRow", "db.Exec",
            "db.Prepare", "tx.Query", "tx.Exec",
            "sqlx.Select", "sqlx.Get", "gorm.Raw",
        }),
    },
    "command_injection": {
        "python": frozenset({
            "os.system", "os.popen", "subprocess.call",
            "subprocess.run", "subprocess.Popen", "exec", "eval",
            "os.execvp", "commands.getoutput",
        }),
        "javascript": frozenset({
            "exec", "execSync", "spawn", "spawnSync",
            "child_process.exec", "child_process.execSync",
            "eval", "Function", "setTimeout", "setInterval",
        }),
        "java": frozenset({
            "Runtime.exec", "ProcessBuilder", "Runtime.getRuntime",
        }),
        "go": frozenset({
            "exec.Command", "exec.CommandContext", "os.StartProcess",
        }),
    },
    "xss": {
        "python": frozenset({
            "render_template_string", "Markup", "innerHTML",
            "Response", "make_response", "jsonify",
        }),
        "javascript": frozenset({
            "innerHTML", "outerHTML", "document.write",
            "document.writeln", "insertAdjacentHTML",
            "res.send", "res.write", "res.end", "dangerouslySetInnerHTML",
        }),
        "java": frozenset({
            "response.getWriter", "out.println", "out.print",
            "PrintWriter.write", "response.getOutputStream",
        }),
        "go": frozenset({
            "fmt.Fprintf", "template.HTML", "w.Write",
            "io.WriteString", "http.ResponseWriter",
        }),
    },
    "path_traversal": {
        "python": frozenset({
            "open", "os.path.join", "pathlib.Path", "send_file",
            "send_from_directory", "shutil.copy",
        }),
        "javascript": frozenset({
            "fs.readFile", "fs.readFileSync", "fs.writeFile",
            "fs.createReadStream", "path.join", "path.resolve",
            "res.sendFile", "express.static",
        }),
        "java": frozenset({
            "FileInputStream", "FileOutputStream", "File",
            "Paths.get", "Files.readAllBytes", "Files.newInputStream",
        }),
        "go": frozenset({
            "os.Open", "os.ReadFile", "ioutil.ReadFile",
            "filepath.Join", "http.ServeFile",
        }),
    },
    "ssrf": {
        "python": frozenset({
            "requests.get", "requests.post", "urllib.request.urlopen",
            "http.client.HTTPConnection", "httpx.get", "httpx.post",
            "aiohttp.ClientSession",
        }),
        "javascript": frozenset({
            "fetch", "axios.get", "axios.post", "http.get",
            "https.get", "request", "got", "node-fetch",
            "superagent",
        }),
        "java": frozenset({
            "URL.openConnection", "HttpURLConnection",
            "HttpClient", "RestTemplate", "WebClient",
            "OkHttpClient", "Apache.HttpClient",
        }),
        "go": frozenset({
            "http.Get", "http.Post", "http.NewRequest",
            "http.Client.Do", "net.Dial", "rpc.Dial",
        }),
    },
    "deserialization": {
        "python": frozenset({
            "pickle.loads", "pickle.load", "yaml.load",
            "yaml.unsafe_load", "marshal.loads", "shelve.open",
        }),
        "javascript": frozenset({
            "JSON.parse", "unserialize", "deserialize",
        }),
        "java": frozenset({
            "ObjectInputStream", "readObject", "XMLDecoder",
            "XStream.fromXML", "Gson.fromJson", "ObjectMapper.readValue",
        }),
        "go": frozenset({
            "json.Unmarshal", "xml.Unmarshal", "gob.Decode",
            "encoding.Decode",
        }),
    },
}

# Sanitizers: functions that neutralize tainted data
_SANITIZERS: Dict[str, FrozenSet[str]] = {
    "python": frozenset({
        "escape", "html.escape", "markupsafe.escape", "bleach.clean",
        "quote", "urllib.parse.quote", "parameterized", "sanitize",
        "validate", "clean", "strip_tags", "Markup.escape",
    }),
    "javascript": frozenset({
        "escape", "encodeURIComponent", "encodeURI",
        "DOMPurify.sanitize", "sanitize", "validator.escape",
        "xss", "he.encode", "htmlEntities",
    }),
    "java": frozenset({
        "PreparedStatement", "setParameter", "Encoder.encode",
        "StringEscapeUtils", "HtmlUtils.htmlEscape",
        "ESAPI.encoder", "Jsoup.clean", "sanitize",
    }),
    "go": frozenset({
        "html.EscapeString", "template.HTMLEscapeString",
        "url.QueryEscape", "url.PathEscape",
        "sqlx.Rebind", "pgx.Sanitize",
    }),
}


@dataclass
class DataFlowPath:
    """Represents a data flow path from source to sink."""

    source: str
    sink: str
    path: List[str]
    is_tainted: bool
    sanitization_points: List[str] = field(default_factory=list)
    language: str = "unknown"
    vuln_type: str = "unknown"
    confidence: float = 0.0  # 0.0–1.0


@dataclass
class DataFlowResult:
    """Result of data flow analysis."""

    has_path: bool
    paths: List[DataFlowPath] = field(default_factory=list)
    max_depth: int = 0
    sanitization_found: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_path_for_function(self, func_name: str) -> Optional[List[str]]:
        for path in self.paths:
            if func_name in path.path:
                return path.path
        return None

    @property
    def worst_confidence(self) -> float:
        if not self.paths:
            return 0.0
        return max(p.confidence for p in self.paths)

    @property
    def tainted_sinks(self) -> List[str]:
        return [p.sink for p in self.paths if p.is_tainted and not p.sanitization_points]


class DataFlowAnalyzer:
    """Analyze data flow for exploitability verification.

    Performs cross-language taint tracking from user-controlled input
    sources to dangerous operation sinks.
    """

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        self.config = config or {}
        self.max_path_length = self.config.get("max_path_length", 20)
        self.enable_taint_analysis = self.config.get("enable_taint_analysis", True)

    def analyze_data_flow(
        self,
        repo_path: Path,
        vulnerable_pattern: Any,
        call_graph: Dict[str, Any],
    ) -> DataFlowResult:
        """Analyze data flow for a vulnerable pattern using the call graph."""
        vuln_type = getattr(vulnerable_pattern, "pattern_type", "unknown")

        # Determine language from call graph nodes
        language = self._detect_language(call_graph)

        # Run taint analysis for the specific vulnerability type
        paths = self._analyze_taint(repo_path, vuln_type, language, call_graph)

        return DataFlowResult(
            has_path=len(paths) > 0,
            paths=paths,
            max_depth=max(len(p.path) for p in paths) if paths else 0,
            sanitization_found=any(p.sanitization_points for p in paths),
            metadata={
                "language": language,
                "vuln_type": vuln_type,
                "sources_checked": len(_SOURCES.get(language, set())),
                "sinks_checked": len(
                    _SINKS.get(vuln_type, {}).get(language, set())
                ),
            },
        )

    def analyze_all_flows(
        self,
        repo_path: Path,
        call_graph: Dict[str, Any],
    ) -> Dict[str, DataFlowResult]:
        """Analyze data flow for ALL vulnerability types at once.

        Returns a dict of vuln_type → DataFlowResult.
        """
        language = self._detect_language(call_graph)
        results: Dict[str, DataFlowResult] = {}

        for vuln_type in _SINKS:
            paths = self._analyze_taint(repo_path, vuln_type, language, call_graph)
            results[vuln_type] = DataFlowResult(
                has_path=len(paths) > 0,
                paths=paths,
                max_depth=max(len(p.path) for p in paths) if paths else 0,
                sanitization_found=any(p.sanitization_points for p in paths),
                metadata={"language": language, "vuln_type": vuln_type},
            )

        return results

    # ────────────────── Internal ──────────────────

    def _detect_language(self, call_graph: Dict[str, Any]) -> str:
        lang_counts: Dict[str, int] = {}
        for node in call_graph.values():
            lang = node.get("language", "python")
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
        if not lang_counts:
            return "python"
        return max(lang_counts.items(), key=lambda x: x[1])[0]

    def _analyze_taint(
        self,
        repo_path: Path,
        vuln_type: str,
        language: str,
        call_graph: Dict[str, Any],
    ) -> List[DataFlowPath]:
        """Core taint analysis: find paths from sources to sinks through the call graph."""
        paths: List[DataFlowPath] = []

        sources = _SOURCES.get(language, set())
        sinks = _SINKS.get(vuln_type, {}).get(language, set())
        sanitizers = _SANITIZERS.get(language, set())

        if not sources or not sinks:
            return paths

        # Find call graph nodes that reference sources or sinks
        source_nodes: Set[str] = set()
        sink_nodes: Set[str] = set()
        sanitizer_nodes: Set[str] = set()

        for func_name, node in call_graph.items():
            # Check if function name or its callees match source/sink patterns
            func_lower = func_name.lower()
            for s in sources:
                if s.lower() in func_lower or any(
                    s.lower() in c.get("function", "").lower()
                    for c in node.get("callees", [])
                ):
                    source_nodes.add(func_name)

            for s in sinks:
                if s.lower() in func_lower or any(
                    s.lower() in c.get("function", "").lower()
                    for c in node.get("callees", [])
                ):
                    sink_nodes.add(func_name)

            for s in sanitizers:
                if s.lower() in func_lower or any(
                    s.lower() in c.get("function", "").lower()
                    for c in node.get("callees", [])
                ):
                    sanitizer_nodes.add(func_name)

        # Also scan actual file contents for source/sink/sanitizer patterns
        self._scan_files_for_patterns(
            repo_path, language, sources, sinks, sanitizers,
            source_nodes, sink_nodes, sanitizer_nodes, call_graph,
        )

        # For each source, BFS to each reachable sink
        for src in source_nodes:
            for snk in sink_nodes:
                reachable, chain = self._bfs_taint(
                    call_graph, src, snk, self.max_path_length
                )
                if reachable:
                    # Check if any sanitizer is on the path
                    path_sanitizers = [
                        n for n in chain if n in sanitizer_nodes
                    ]
                    confidence = self._compute_confidence(
                        chain, path_sanitizers, vuln_type
                    )
                    paths.append(
                        DataFlowPath(
                            source=src,
                            sink=snk,
                            path=chain,
                            is_tainted=len(path_sanitizers) == 0,
                            sanitization_points=path_sanitizers,
                            language=language,
                            vuln_type=vuln_type,
                            confidence=confidence,
                        )
                    )

        return paths

    def _scan_files_for_patterns(
        self,
        repo_path: Path,
        language: str,
        sources: FrozenSet[str],
        sinks: FrozenSet[str],
        sanitizers: FrozenSet[str],
        source_nodes: Set[str],
        sink_nodes: Set[str],
        sanitizer_nodes: Set[str],
        call_graph: Dict[str, Any],
    ) -> None:
        """Scan file contents for source/sink/sanitizer patterns in function bodies."""
        ext_map = {
            "python": ("*.py",),
            "javascript": ("*.js", "*.ts", "*.jsx", "*.tsx"),
            "java": ("*.java",),
            "go": ("*.go",),
        }
        extensions = ext_map.get(language, ())
        if not extensions:
            return

        # Build pattern regexes for efficiency
        source_pattern = re.compile(
            "|".join(re.escape(s.split(".")[-1]) for s in sources),
            re.IGNORECASE,
        )
        sink_pattern = re.compile(
            "|".join(re.escape(s.split(".")[-1]) for s in sinks),
            re.IGNORECASE,
        )
        sanitizer_pattern = re.compile(
            "|".join(re.escape(s.split(".")[-1]) for s in sanitizers),
            re.IGNORECASE,
        )

        for ext in extensions:
            for f in list(repo_path.rglob(ext))[:2000]:
                if any(part in {"node_modules", ".venv", "vendor", ".git", "test", "tests"} for part in f.parts):
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                # For each function in the call graph from this file,
                # check if their body contains sources/sinks
                rel = str(f)
                for func_name, node in call_graph.items():
                    if node.get("file", "") not in rel:
                        continue
                    func_lower = func_name.lower()
                    # Check if function body has sources
                    if source_pattern.search(func_lower):
                        source_nodes.add(func_name)
                    if sink_pattern.search(func_lower):
                        sink_nodes.add(func_name)
                    if sanitizer_pattern.search(func_lower):
                        sanitizer_nodes.add(func_name)

    @staticmethod
    def _bfs_taint(
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
            # Also check callers (bidirectional for taint)
            for caller in node.get("callers", []):
                caller_name = caller.get("function", "")
                if caller_name and caller_name not in visited:
                    queue.append((caller_name, path + [caller_name]))

        return False, []

    @staticmethod
    def _compute_confidence(
        chain: List[str], sanitizers: List[str], vuln_type: str
    ) -> float:
        """Compute confidence score (0.0–1.0) for a taint path."""
        # Shorter paths = higher confidence
        length_score = max(0.3, 1.0 - (len(chain) - 2) * 0.1)

        # Sanitized paths = lower confidence of exploitability
        if sanitizers:
            length_score *= 0.3

        # SQL injection and command injection are higher confidence
        type_multiplier = {
            "sql_injection": 1.0,
            "command_injection": 1.0,
            "xss": 0.9,
            "ssrf": 0.95,
            "path_traversal": 0.85,
            "deserialization": 0.8,
        }.get(vuln_type, 0.7)

        return round(min(1.0, length_score * type_multiplier), 3)
