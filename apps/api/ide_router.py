"""
IDE extension support API endpoints with real code analysis.

This module provides production-ready IDE integration with:
- Real-time code analysis using pattern matching and AST parsing
- Security vulnerability detection
- Code quality metrics calculation
- Intelligent code suggestions
- SARIF format support for findings
"""
import ast
import hashlib
import logging
import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ide", tags=["ide"])


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Finding category types."""

    SECURITY = "security"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    STYLE = "style"
    BEST_PRACTICE = "best_practice"


@dataclass
class SecurityPattern:
    """Security vulnerability pattern."""

    pattern: str
    severity: Severity
    category: FindingCategory
    message: str
    cwe_id: Optional[str] = None
    fix_suggestion: Optional[str] = None


# Security patterns for different languages
SECURITY_PATTERNS: Dict[str, List[SecurityPattern]] = {
    "python": [
        SecurityPattern(
            pattern=r"eval\s*\(",
            severity=Severity.CRITICAL,
            category=FindingCategory.SECURITY,
            message="Use of eval() can lead to code injection vulnerabilities",
            cwe_id="CWE-94",
            fix_suggestion="Use ast.literal_eval() for safe evaluation of literals",
        ),
        SecurityPattern(
            pattern=r"exec\s*\(",
            severity=Severity.CRITICAL,
            category=FindingCategory.SECURITY,
            message="Use of exec() can lead to code injection vulnerabilities",
            cwe_id="CWE-94",
            fix_suggestion="Avoid exec() and use safer alternatives",
        ),
        SecurityPattern(
            pattern=r"subprocess\..*shell\s*=\s*True",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
            message="Shell=True in subprocess can lead to command injection",
            cwe_id="CWE-78",
            fix_suggestion="Use shell=False and pass arguments as a list",
        ),
        SecurityPattern(
            pattern=r"pickle\.loads?\s*\(",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
            message="Pickle deserialization can execute arbitrary code",
            cwe_id="CWE-502",
            fix_suggestion="Use JSON or other safe serialization formats",
        ),
        SecurityPattern(
            pattern=r"yaml\.load\s*\([^)]*\)",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
            message="yaml.load() without Loader can execute arbitrary code",
            cwe_id="CWE-502",
            fix_suggestion="Use yaml.safe_load() instead",
        ),
        SecurityPattern(
            pattern=r"hashlib\.(md5|sha1)\s*\(",
            severity=Severity.MEDIUM,
            category=FindingCategory.SECURITY,
            message="Weak hash algorithm detected",
            cwe_id="CWE-328",
            fix_suggestion="Use SHA-256 or stronger hash algorithms",
        ),
        SecurityPattern(
            pattern=r"password\s*=\s*['\"][^'\"]+['\"]",
            severity=Severity.CRITICAL,
            category=FindingCategory.SECURITY,
            message="Hardcoded password detected",
            cwe_id="CWE-798",
            fix_suggestion="Use environment variables or secure vaults for credentials",
        ),
        SecurityPattern(
            pattern=r"(api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]",
            severity=Severity.CRITICAL,
            category=FindingCategory.SECURITY,
            message="Hardcoded secret detected",
            cwe_id="CWE-798",
            fix_suggestion="Use environment variables or secure vaults for secrets",
        ),
        SecurityPattern(
            pattern=r"\.execute\s*\([^)]*%[^)]*\)",
            severity=Severity.CRITICAL,
            category=FindingCategory.SECURITY,
            message="Potential SQL injection with string formatting",
            cwe_id="CWE-89",
            fix_suggestion="Use parameterized queries instead",
        ),
        SecurityPattern(
            pattern=r"assert\s+",
            severity=Severity.LOW,
            category=FindingCategory.SECURITY,
            message="Assert statements are removed in optimized mode",
            cwe_id="CWE-617",
            fix_suggestion="Use proper validation instead of assert for security checks",
        ),
    ],
    "javascript": [
        SecurityPattern(
            pattern=r"eval\s*\(",
            severity=Severity.CRITICAL,
            category=FindingCategory.SECURITY,
            message="Use of eval() can lead to code injection",
            cwe_id="CWE-94",
            fix_suggestion="Use JSON.parse() for JSON data or safer alternatives",
        ),
        SecurityPattern(
            pattern=r"innerHTML\s*=",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
            message="innerHTML can lead to XSS vulnerabilities",
            cwe_id="CWE-79",
            fix_suggestion="Use textContent or sanitize HTML input",
        ),
        SecurityPattern(
            pattern=r"document\.write\s*\(",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
            message="document.write can lead to XSS vulnerabilities",
            cwe_id="CWE-79",
            fix_suggestion="Use DOM manipulation methods instead",
        ),
        SecurityPattern(
            pattern=r"new\s+Function\s*\(",
            severity=Severity.CRITICAL,
            category=FindingCategory.SECURITY,
            message="new Function() can execute arbitrary code",
            cwe_id="CWE-94",
            fix_suggestion="Avoid dynamic function creation",
        ),
        SecurityPattern(
            pattern=r"localStorage\.setItem\s*\([^)]*password",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
            message="Storing passwords in localStorage is insecure",
            cwe_id="CWE-922",
            fix_suggestion="Use secure session management instead",
        ),
    ],
    "typescript": [],  # Inherits from JavaScript
    "java": [
        SecurityPattern(
            pattern=r"Runtime\.getRuntime\(\)\.exec\s*\(",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
            message="Command execution can lead to injection vulnerabilities",
            cwe_id="CWE-78",
            fix_suggestion="Validate and sanitize all input before execution",
        ),
        SecurityPattern(
            pattern=r"new\s+ObjectInputStream\s*\(",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
            message="Deserialization can lead to remote code execution",
            cwe_id="CWE-502",
            fix_suggestion="Use safe deserialization libraries with whitelisting",
        ),
    ],
    "go": [
        SecurityPattern(
            pattern=r"exec\.Command\s*\([^)]*\+",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
            message="Command injection vulnerability with string concatenation",
            cwe_id="CWE-78",
            fix_suggestion="Use parameterized commands",
        ),
    ],
    "rust": [
        SecurityPattern(
            pattern=r"unsafe\s*\{",
            severity=Severity.MEDIUM,
            category=FindingCategory.SECURITY,
            message="Unsafe block detected - review carefully",
            cwe_id="CWE-119",
            fix_suggestion="Minimize unsafe code and document safety invariants",
        ),
    ],
}


class IDEConfigResponse(BaseModel):
    """Response model for IDE configuration."""

    api_endpoint: str
    supported_languages: List[str]
    features: Dict[str, bool]
    version: str = "2.0.0"
    analysis_capabilities: List[str] = Field(default_factory=list)


class CodeAnalysisRequest(BaseModel):
    """Request model for code analysis."""

    file_path: str
    content: str
    language: str
    include_metrics: bool = True
    include_suggestions: bool = True
    severity_threshold: Optional[str] = None


class Finding(BaseModel):
    """Code analysis finding."""

    rule_id: str
    message: str
    severity: str
    category: str
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    cwe_id: Optional[str] = None
    fix_suggestion: Optional[str] = None
    code_snippet: Optional[str] = None


class Suggestion(BaseModel):
    """Code improvement suggestion."""

    type: str
    message: str
    line: int
    priority: str
    auto_fixable: bool = False
    fix_code: Optional[str] = None


class CodeMetrics(BaseModel):
    """Code quality metrics."""

    lines_of_code: int
    lines_of_comments: int
    blank_lines: int
    cyclomatic_complexity: int
    cognitive_complexity: int
    maintainability_index: float
    function_count: int
    class_count: int
    import_count: int
    max_nesting_depth: int


class CodeAnalysisResponse(BaseModel):
    """Response model for code analysis."""

    findings: List[Finding]
    suggestions: List[Suggestion]
    metrics: CodeMetrics
    analysis_time_ms: float
    file_hash: str


class SuggestionResponse(BaseModel):
    """Response model for code suggestions."""

    suggestions: List[Dict[str, Any]]
    context: Dict[str, Any]
    analysis_time_ms: float


def calculate_cyclomatic_complexity(content: str, language: str) -> int:
    """Calculate cyclomatic complexity of code."""
    complexity = 1  # Base complexity

    # Decision points that increase complexity
    decision_patterns = [
        r"\bif\b",
        r"\belif\b",
        r"\belse\b",
        r"\bfor\b",
        r"\bwhile\b",
        r"\band\b",
        r"\bor\b",
        r"\btry\b",
        r"\bexcept\b",
        r"\bcase\b",
        r"\bswitch\b",
        r"\?\s*:",
        r"\?\?",  # Ternary and null coalescing
    ]

    for pattern in decision_patterns:
        complexity += len(re.findall(pattern, content))

    return complexity


def calculate_cognitive_complexity(content: str, language: str) -> int:
    """Calculate cognitive complexity (how hard code is to understand)."""
    complexity = 0
    nesting_level = 0

    lines = content.split("\n")
    for line in lines:
        stripped = line.strip()

        # Increase nesting for control structures
        if re.search(r"\b(if|for|while|try|switch)\b", stripped):
            complexity += 1 + nesting_level
            nesting_level += 1

        # Decrease nesting for closing blocks
        if stripped.startswith("}") or stripped == "end":
            nesting_level = max(0, nesting_level - 1)

        # Additional complexity for logical operators
        complexity += len(re.findall(r"\b(and|or|&&|\|\|)\b", stripped))

        # Recursion adds complexity
        if re.search(r"def\s+(\w+).*\1\s*\(", content):
            complexity += 2

    return complexity


def calculate_maintainability_index(loc: int, complexity: int, comments: int) -> float:
    """Calculate maintainability index (0-100 scale)."""
    import math

    if loc == 0:
        return 100.0

    # Simplified Halstead volume approximation
    volume = loc * math.log2(max(loc, 1))

    # Comment ratio bonus
    comment_ratio = comments / max(loc, 1)

    # MI formula (simplified)
    mi = (
        171
        - 5.2 * math.log(max(volume, 1))
        - 0.23 * complexity
        + 16.2 * math.log(max(comment_ratio + 0.01, 0.01))
    )

    # Normalize to 0-100
    return max(0, min(100, mi))


def count_nesting_depth(content: str) -> int:
    """Count maximum nesting depth."""
    max_depth = 0
    current_depth = 0

    for char in content:
        if char in "{(":
            current_depth += 1
            max_depth = max(max_depth, current_depth)
        elif char in "})":
            current_depth = max(0, current_depth - 1)

    return max_depth


def analyze_python_ast(content: str) -> Tuple[int, int, int]:
    """Analyze Python code using AST for accurate counts."""
    try:
        tree = ast.parse(content)

        function_count = sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        class_count = sum(
            1 for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
        )
        import_count = sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        )

        return function_count, class_count, import_count
    except SyntaxError:
        # Fallback to regex-based counting
        function_count = len(re.findall(r"\bdef\s+\w+", content))
        class_count = len(re.findall(r"\bclass\s+\w+", content))
        import_count = len(re.findall(r"\b(import|from)\s+", content))
        return function_count, class_count, import_count


def calculate_metrics(content: str, language: str) -> CodeMetrics:
    """Calculate comprehensive code metrics."""
    lines = content.split("\n")

    loc = 0
    comments = 0
    blank = 0

    in_multiline_comment = False

    for line in lines:
        stripped = line.strip()

        if not stripped:
            blank += 1
            continue

        # Handle multiline comments
        if language == "python":
            if '"""' in stripped or "'''" in stripped:
                in_multiline_comment = not in_multiline_comment
                comments += 1
                continue
        elif language in ("javascript", "typescript", "java", "go"):
            if "/*" in stripped:
                in_multiline_comment = True
            if "*/" in stripped:
                in_multiline_comment = False
                comments += 1
                continue

        if in_multiline_comment:
            comments += 1
            continue

        # Single line comments
        if language == "python" and stripped.startswith("#"):
            comments += 1
        elif language in (
            "javascript",
            "typescript",
            "java",
            "go",
            "rust",
        ) and stripped.startswith("//"):
            comments += 1
        else:
            loc += 1

    cyclomatic = calculate_cyclomatic_complexity(content, language)
    cognitive = calculate_cognitive_complexity(content, language)
    maintainability = calculate_maintainability_index(loc, cyclomatic, comments)
    nesting = count_nesting_depth(content)

    # Language-specific analysis
    if language == "python":
        func_count, class_count, import_count = analyze_python_ast(content)
    else:
        func_count = len(re.findall(r"\b(function|def|func|fn)\s+\w+", content))
        class_count = len(re.findall(r"\bclass\s+\w+", content))
        import_count = len(re.findall(r"\b(import|require|use)\s+", content))

    return CodeMetrics(
        lines_of_code=loc,
        lines_of_comments=comments,
        blank_lines=blank,
        cyclomatic_complexity=cyclomatic,
        cognitive_complexity=cognitive,
        maintainability_index=round(maintainability, 2),
        function_count=func_count,
        class_count=class_count,
        import_count=import_count,
        max_nesting_depth=nesting,
    )


def find_security_issues(
    content: str, language: str, severity_threshold: Optional[str] = None
) -> List[Finding]:
    """Find security issues in code using pattern matching."""
    findings: List[Finding] = []

    # Get patterns for the language
    patterns = SECURITY_PATTERNS.get(language, [])

    # TypeScript inherits JavaScript patterns
    if language == "typescript":
        patterns = patterns + SECURITY_PATTERNS.get("javascript", [])

    # Severity ordering for filtering
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    threshold_level = 4  # Default: include all
    if severity_threshold:
        threshold_level = severity_order.get(Severity(severity_threshold), 4)

    lines = content.split("\n")

    for pattern_def in patterns:
        # Check severity threshold
        if severity_order.get(pattern_def.severity, 4) > threshold_level:
            continue

        for line_num, line in enumerate(lines, 1):
            matches = list(re.finditer(pattern_def.pattern, line, re.IGNORECASE))
            for match in matches:
                # Get code snippet context
                start_line = max(0, line_num - 2)
                end_line = min(len(lines), line_num + 2)
                snippet = "\n".join(lines[start_line:end_line])

                findings.append(
                    Finding(
                        rule_id=f"SEC-{pattern_def.cwe_id or 'UNKNOWN'}",
                        message=pattern_def.message,
                        severity=pattern_def.severity.value,
                        category=pattern_def.category.value,
                        line=line_num,
                        column=match.start() + 1,
                        end_line=line_num,
                        end_column=match.end() + 1,
                        cwe_id=pattern_def.cwe_id,
                        fix_suggestion=pattern_def.fix_suggestion,
                        code_snippet=snippet,
                    )
                )

    return findings


def generate_suggestions(
    content: str, language: str, metrics: CodeMetrics
) -> List[Suggestion]:
    """Generate code improvement suggestions."""
    suggestions: List[Suggestion] = []

    # Complexity suggestions
    if metrics.cyclomatic_complexity > 10:
        suggestions.append(
            Suggestion(
                type="refactoring",
                message=f"High cyclomatic complexity ({metrics.cyclomatic_complexity}). Consider breaking down into smaller functions.",
                line=1,
                priority="high",
                auto_fixable=False,
            )
        )

    if metrics.cognitive_complexity > 15:
        suggestions.append(
            Suggestion(
                type="refactoring",
                message=f"High cognitive complexity ({metrics.cognitive_complexity}). Code may be hard to understand.",
                line=1,
                priority="medium",
                auto_fixable=False,
            )
        )

    # Nesting depth suggestions
    if metrics.max_nesting_depth > 4:
        suggestions.append(
            Suggestion(
                type="refactoring",
                message=f"Deep nesting detected (depth: {metrics.max_nesting_depth}). Consider early returns or extracting methods.",
                line=1,
                priority="medium",
                auto_fixable=False,
            )
        )

    # Comment ratio suggestions
    if (
        metrics.lines_of_code > 50
        and metrics.lines_of_comments < metrics.lines_of_code * 0.1
    ):
        suggestions.append(
            Suggestion(
                type="documentation",
                message="Low comment ratio. Consider adding documentation for complex logic.",
                line=1,
                priority="low",
                auto_fixable=False,
            )
        )

    # Function length suggestions (check for long functions)
    lines = content.split("\n")
    func_start = None
    func_name = ""

    for i, line in enumerate(lines):
        if re.match(r"\s*(def|function|func)\s+(\w+)", line):
            if func_start is not None and i - func_start > 50:
                suggestions.append(
                    Suggestion(
                        type="refactoring",
                        message=f"Function '{func_name}' is too long ({i - func_start} lines). Consider splitting.",
                        line=func_start + 1,
                        priority="medium",
                        auto_fixable=False,
                    )
                )
            match = re.match(r"\s*(def|function|func)\s+(\w+)", line)
            if match:
                func_name = match.group(2)
            func_start = i

    # Maintainability suggestions
    if metrics.maintainability_index < 50:
        suggestions.append(
            Suggestion(
                type="quality",
                message=f"Low maintainability index ({metrics.maintainability_index}). Code may be difficult to maintain.",
                line=1,
                priority="high",
                auto_fixable=False,
            )
        )

    return suggestions


@router.get("/config", response_model=IDEConfigResponse)
async def get_ide_config() -> IDEConfigResponse:
    """Get IDE extension configuration with full capabilities."""
    return IDEConfigResponse(
        api_endpoint="/api/v1/ide",
        supported_languages=[
            "python",
            "javascript",
            "typescript",
            "java",
            "go",
            "rust",
        ],
        features={
            "real_time_analysis": True,
            "inline_suggestions": True,
            "auto_fix": True,
            "security_scanning": True,
            "metrics_calculation": True,
            "sarif_export": True,
        },
        version="2.0.0",
        analysis_capabilities=[
            "security_vulnerability_detection",
            "code_quality_metrics",
            "cyclomatic_complexity",
            "cognitive_complexity",
            "maintainability_index",
            "pattern_based_analysis",
            "ast_analysis_python",
        ],
    )


@router.post("/analyze", response_model=CodeAnalysisResponse)
async def analyze_code(request: CodeAnalysisRequest) -> CodeAnalysisResponse:
    """Analyze code in real-time with comprehensive security and quality checks."""
    start_time = time.time()

    # Validate language
    supported_languages = ["python", "javascript", "typescript", "java", "go", "rust"]
    if request.language.lower() not in supported_languages:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported language: {request.language}. Supported: {supported_languages}",
        )

    language = request.language.lower()
    content = request.content

    # Calculate file hash for caching/deduplication
    file_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

    # Calculate metrics
    metrics = (
        calculate_metrics(content, language)
        if request.include_metrics
        else CodeMetrics(
            lines_of_code=len(content.split("\n")),
            lines_of_comments=0,
            blank_lines=0,
            cyclomatic_complexity=0,
            cognitive_complexity=0,
            maintainability_index=0.0,
            function_count=0,
            class_count=0,
            import_count=0,
            max_nesting_depth=0,
        )
    )

    # Find security issues
    findings = find_security_issues(content, language, request.severity_threshold)

    # Generate suggestions
    suggestions = (
        generate_suggestions(content, language, metrics)
        if request.include_suggestions
        else []
    )

    analysis_time = (time.time() - start_time) * 1000

    logger.info(
        f"Analyzed {request.file_path}: {len(findings)} findings, "
        f"{len(suggestions)} suggestions in {analysis_time:.2f}ms"
    )

    return CodeAnalysisResponse(
        findings=findings,
        suggestions=suggestions,
        metrics=metrics,
        analysis_time_ms=round(analysis_time, 2),
        file_hash=file_hash,
    )


@router.get("/suggestions", response_model=SuggestionResponse)
async def get_suggestions(
    file_path: str,
    line: int,
    column: int,
    content: Optional[str] = None,
    language: Optional[str] = None,
) -> SuggestionResponse:
    """Get context-aware code suggestions for cursor position."""
    start_time = time.time()

    suggestions: List[Dict[str, Any]] = []

    # If content is provided, analyze the specific line
    if content and language:
        lines = content.split("\n")
        if 0 < line <= len(lines):
            current_line = lines[line - 1]

            # Detect what the user might be typing
            before_cursor = (
                current_line[:column] if column <= len(current_line) else current_line
            )

            # Python-specific suggestions
            if language.lower() == "python":
                if before_cursor.strip().endswith("def "):
                    suggestions.append(
                        {
                            "type": "snippet",
                            "label": "Function with docstring",
                            "insert_text": 'function_name(self):\n    """Description."""\n    pass',
                            "documentation": "Create a function with docstring template",
                        }
                    )

                if "import" in before_cursor:
                    suggestions.append(
                        {
                            "type": "import",
                            "label": "from typing import",
                            "insert_text": "from typing import List, Dict, Optional",
                            "documentation": "Import common typing constructs",
                        }
                    )

                if before_cursor.strip().startswith("class "):
                    suggestions.append(
                        {
                            "type": "snippet",
                            "label": "Class with __init__",
                            "insert_text": "ClassName:\n    def __init__(self):\n        pass",
                            "documentation": "Create a class with constructor",
                        }
                    )

            # Security-aware suggestions
            if "password" in before_cursor.lower():
                suggestions.append(
                    {
                        "type": "security",
                        "label": "Use environment variable",
                        "insert_text": "os.environ.get('PASSWORD')",
                        "documentation": "Store sensitive data in environment variables",
                        "priority": "high",
                    }
                )

            if "sql" in before_cursor.lower() or "query" in before_cursor.lower():
                suggestions.append(
                    {
                        "type": "security",
                        "label": "Use parameterized query",
                        "insert_text": "cursor.execute('SELECT * FROM table WHERE id = ?', (id,))",
                        "documentation": "Prevent SQL injection with parameterized queries",
                        "priority": "high",
                    }
                )

    analysis_time = (time.time() - start_time) * 1000

    return SuggestionResponse(
        suggestions=suggestions,
        context={
            "file_path": file_path,
            "line": line,
            "column": column,
            "language": language,
        },
        analysis_time_ms=round(analysis_time, 2),
    )


@router.post("/sarif")
async def export_sarif(request: CodeAnalysisRequest) -> Dict[str, Any]:
    """Export analysis results in SARIF format for CI/CD integration."""
    # Run analysis
    analysis = await analyze_code(request)

    # Convert to SARIF format
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FixOps IDE Analyzer",
                        "version": "2.0.0",
                        "informationUri": "https://fixops.io",
                        "rules": [
                            {
                                "id": finding.rule_id,
                                "shortDescription": {"text": finding.message},
                                "defaultConfiguration": {
                                    "level": "error"
                                    if finding.severity in ("critical", "high")
                                    else "warning"
                                },
                            }
                            for finding in analysis.findings
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": finding.rule_id,
                        "level": "error"
                        if finding.severity in ("critical", "high")
                        else "warning",
                        "message": {"text": finding.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": request.file_path},
                                    "region": {
                                        "startLine": finding.line,
                                        "startColumn": finding.column,
                                        "endLine": finding.end_line or finding.line,
                                        "endColumn": finding.end_column
                                        or finding.column,
                                    },
                                }
                            }
                        ],
                        "fixes": [
                            {
                                "description": {"text": finding.fix_suggestion},
                            }
                        ]
                        if finding.fix_suggestion
                        else [],
                    }
                    for finding in analysis.findings
                ],
            }
        ],
    }

    return sarif
