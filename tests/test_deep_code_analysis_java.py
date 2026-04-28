"""Tests for Java AST analyzer in DeepCodeAnalysisEngine (NEW-G070).

5 tests:
  1. Clean Java file  → 0 findings
  2. SQL injection via executeQuery with concatenation → HIGH finding
  3. Command injection via Runtime.exec with taint source → HIGH finding
  4. DocumentBuilderFactory without setFeature → XXE MEDIUM finding
  5. Class hierarchy + methods parsed correctly
"""
from __future__ import annotations

import importlib
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine():
    mod = importlib.import_module("core.deep_code_analysis_engine")
    importlib.reload(mod)
    for name in dir(mod):
        obj = getattr(mod, name)
        if isinstance(obj, type) and name.endswith("Engine"):
            return obj()
    raise RuntimeError("No Engine class found in deep_code_analysis_engine")


@pytest.fixture
def eng(tmp_path, monkeypatch):
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path / "data"))
    return _engine()


def _java_file(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Test 1 — Clean Java file → 0 findings
# ---------------------------------------------------------------------------

CLEAN_JAVA = """\
package com.example;

public class Calculator {
    private int value;

    public Calculator(int initial) {
        this.value = initial;
    }

    public int add(int x) {
        return this.value + x;
    }

    public int subtract(int x) {
        return this.value - x;
    }
}
"""


def test_clean_java_no_findings(eng, tmp_path):
    jf = _java_file(tmp_path, "Calculator.java", CLEAN_JAVA)
    result = eng._analyze_java(jf)
    assert isinstance(result, dict)
    assert result["findings"] == [], (
        f"Expected 0 findings for clean Java file, got: {result['findings']}"
    )
    assert result["package"] == "com.example"


# ---------------------------------------------------------------------------
# Test 2 — SQL injection: executeQuery with string concatenation → HIGH
# ---------------------------------------------------------------------------

SQL_INJECTION_JAVA = """\
package com.example;

import java.sql.Connection;
import java.sql.Statement;

public class UserDao {
    public void getUser(Connection conn, String userId) throws Exception {
        Statement stmt = conn.createStatement();
        // Vulnerable: string concatenation in SQL query
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }
}
"""


def test_sql_injection_detected(eng, tmp_path):
    jf = _java_file(tmp_path, "UserDao.java", SQL_INJECTION_JAVA)
    result = eng._analyze_java(jf)
    findings = result["findings"]
    sql_findings = [f for f in findings if f["type"] == "SQL_INJECTION"]
    assert len(sql_findings) >= 1, (
        f"Expected at least 1 SQL_INJECTION finding, got findings: {findings}"
    )
    assert sql_findings[0]["severity"] == "HIGH"
    assert sql_findings[0]["cwe"] == "CWE-89"


# ---------------------------------------------------------------------------
# Test 3 — Command injection: Runtime.exec with taint source → HIGH
# ---------------------------------------------------------------------------

CMD_INJECTION_JAVA = """\
package com.example;

import javax.servlet.http.HttpServletRequest;

public class PingServlet {
    public void doGet(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        // Vulnerable: user input passed to exec
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
"""


def test_command_injection_detected(eng, tmp_path):
    jf = _java_file(tmp_path, "PingServlet.java", CMD_INJECTION_JAVA)
    result = eng._analyze_java(jf)
    findings = result["findings"]
    cmd_findings = [f for f in findings if f["type"] == "COMMAND_INJECTION"]
    assert len(cmd_findings) >= 1, (
        f"Expected at least 1 COMMAND_INJECTION finding, got findings: {findings}"
    )
    assert cmd_findings[0]["severity"] == "HIGH"
    assert cmd_findings[0]["cwe"] == "CWE-78"


# ---------------------------------------------------------------------------
# Test 4 — XXE: DocumentBuilderFactory without setFeature → MEDIUM
# ---------------------------------------------------------------------------

XXE_JAVA = """\
package com.example;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

public class XmlParser {
    public void parse(String xml) throws Exception {
        // Vulnerable: no disallow-doctype-decl feature set
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
    }
}
"""

XXE_SAFE_JAVA = """\
package com.example;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

public class SafeXmlParser {
    public void parse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
    }
}
"""


def test_xxe_detected(eng, tmp_path):
    jf = _java_file(tmp_path, "XmlParser.java", XXE_JAVA)
    result = eng._analyze_java(jf)
    findings = result["findings"]
    xxe_findings = [f for f in findings if f["type"] == "XXE"]
    assert len(xxe_findings) >= 1, (
        f"Expected at least 1 XXE finding, got findings: {findings}"
    )
    assert xxe_findings[0]["severity"] == "MEDIUM"
    assert xxe_findings[0]["cwe"] == "CWE-611"


def test_xxe_not_flagged_when_safe_feature_set(eng, tmp_path):
    jf = _java_file(tmp_path, "SafeXmlParser.java", XXE_SAFE_JAVA)
    result = eng._analyze_java(jf)
    xxe_findings = [f for f in result["findings"] if f["type"] == "XXE"]
    assert xxe_findings == [], (
        f"Expected no XXE finding when setFeature is present, got: {xxe_findings}"
    )


# ---------------------------------------------------------------------------
# Test 5 — Class hierarchy + methods parsed
# ---------------------------------------------------------------------------

HIERARCHY_JAVA = """\
package com.example.service;

import java.io.Serializable;

public class OrderService extends BaseService implements Serializable, Auditable {
    private String orderId;
    private int quantity;

    @Override
    public void process(String input) {
        // processing logic
    }

    @Deprecated
    public String getOrderId() {
        return orderId;
    }

    private void validate(int qty, String ref) {
        // validation
    }
}
"""


def test_class_hierarchy_and_methods_parsed(eng, tmp_path):
    jf = _java_file(tmp_path, "OrderService.java", HIERARCHY_JAVA)
    result = eng._analyze_java(jf)

    assert result["package"] == "com.example.service"
    assert "java.io.Serializable" in result["imports"]

    symbols = result["symbols"]
    symbol_names = [s["symbol_name"] for s in symbols]

    # Class must be found
    class_syms = [s for s in symbols if s["symbol_type"] == "class"]
    assert len(class_syms) >= 1
    cls = class_syms[0]
    assert cls["symbol_name"] == "OrderService"
    assert cls["metadata"]["extends"] == "BaseService"
    assert "Serializable" in cls["metadata"]["implements"]
    assert "Auditable" in cls["metadata"]["implements"]

    # Methods must be found
    method_syms = [s for s in symbols if s["symbol_type"] == "method"]
    method_names = [s["symbol_name"] for s in method_syms]
    assert "process" in method_names
    assert "getOrderId" in method_names
    assert "validate" in method_names

    # Annotations surfaced
    get_order_sym = next(s for s in method_syms if s["symbol_name"] == "getOrderId")
    assert "Deprecated" in get_order_sym["metadata"]["annotations"]

    # Fields
    field_syms = [s for s in symbols if s["symbol_type"] == "field"]
    field_names = [s["symbol_name"] for s in field_syms]
    assert "orderId" in field_names
    assert "quantity" in field_names
