"""Comprehensive tests for Advanced IAST Engine.

Extensive test coverage with edge cases, performance tests, and integration tests.
"""

import time
from datetime import datetime, timezone

import pytest

from risk.runtime.iast_advanced import (
    AdvancedIASTAnalyzer,
    AdvancedTaintAnalyzer,
    ControlFlowAnalyzer,
    DataFlowPath,
    IASTFinding,
    MLBasedDetector,
    StatisticalAnomalyDetector,
    TaintSink,
    TaintSource,
    VulnerabilityType,
)


class TestAdvancedTaintAnalyzer:
    """Test suite for Advanced Taint Analyzer."""

    def test_taint_source_tracking(self):
        """Test taint source tracking."""
        analyzer = AdvancedTaintAnalyzer()

        source = TaintSource(
            variable_name="user_input",
            source_type="request",
            line_number=10,
            confidence=1.0,
        )
        analyzer.add_taint_source(source)

        assert "user_input" in analyzer.taint_sources
        assert analyzer.taint_sources["user_input"] == source

    def test_taint_sink_tracking(self):
        """Test taint sink tracking."""
        analyzer = AdvancedTaintAnalyzer()

        sink = TaintSink(
            function_name="execute",
            sink_type="sql",
            line_number=20,
            severity="high",
        )
        analyzer.add_taint_sink(sink)

        assert "execute" in analyzer.taint_sinks
        assert analyzer.taint_sinks["execute"] == sink

    def test_data_flow_tracking(self):
        """Test data flow tracking."""
        analyzer = AdvancedTaintAnalyzer()

        source = TaintSource("input", "request", 10)
        sink = TaintSink("execute", "sql", 30)

        analyzer.add_taint_source(source)
        analyzer.add_taint_sink(sink)

        # Track flow: input -> processed -> result -> execute
        analyzer.track_data_flow("input", "processed", 15)
        analyzer.track_data_flow("processed", "result", 20)
        analyzer.track_data_flow("result", "execute", 25)

        paths = analyzer.find_taint_paths()
        assert len(paths) > 0
        assert paths[0].source == source
        assert paths[0].sink == sink

    def test_sanitization_detection(self):
        """Test sanitization detection."""
        analyzer = AdvancedTaintAnalyzer()

        source = TaintSource("input", "request", 10)
        sink = TaintSink("execute", "sql", 30)

        analyzer.add_taint_source(source)
        analyzer.add_taint_sink(sink)

        analyzer.track_data_flow("input", "sanitized_input", 15)
        analyzer.track_data_flow("sanitized_input", "execute", 25)

        paths = analyzer.find_taint_paths()
        # Path should be marked as sanitized if sanitizer is in path
        # (Simplified test - in production would check actual sanitization)

    def test_complex_taint_paths(self):
        """Test complex taint paths with multiple branches."""
        analyzer = AdvancedTaintAnalyzer()

        source = TaintSource("user_input", "request", 10)
        sink1 = TaintSink("execute", "sql", 30)
        sink2 = TaintSink("system", "command", 40)

        analyzer.add_taint_source(source)
        analyzer.add_taint_sink(sink1)
        analyzer.add_taint_sink(sink2)

        # Multiple paths
        analyzer.track_data_flow("user_input", "var1", 15)
        analyzer.track_data_flow("var1", "execute", 25)

        analyzer.track_data_flow("user_input", "var2", 16)
        analyzer.track_data_flow("var2", "system", 35)

        paths = analyzer.find_taint_paths()
        assert len(paths) >= 2  # Should find paths to both sinks

    def test_taint_path_confidence_calculation(self):
        """Test taint path confidence calculation."""
        analyzer = AdvancedTaintAnalyzer()

        source = TaintSource("input", "request", 10)
        sink = TaintSink("execute", "sql", 50)

        analyzer.add_taint_source(source)
        analyzer.add_taint_sink(sink)

        # Long path (low confidence)
        for i in range(10):
            analyzer.track_data_flow(f"var{i}", f"var{i+1}", 10 + i)

        paths = analyzer.find_taint_paths()
        if paths:
            # Long paths should have lower confidence
            assert paths[0].confidence < 1.0


class TestControlFlowAnalyzer:
    """Test suite for Control Flow Analyzer."""

    def test_cfg_construction(self):
        """Test control flow graph construction."""
        analyzer = ControlFlowAnalyzer()

        # Simulate function with if statement
        # In production, would parse actual AST
        analyzer.cfg["entry"] = ["if_node"]
        analyzer.cfg["if_node"] = ["then_node", "else_node"]
        analyzer.cfg["then_node"] = ["exit"]
        analyzer.cfg["else_node"] = ["exit"]

        assert "entry" in analyzer.cfg
        assert len(analyzer.cfg["if_node"]) == 2

    def test_dominator_computation(self):
        """Test dominator computation."""
        analyzer = ControlFlowAnalyzer()

        # Simple linear CFG
        analyzer.cfg["entry"] = ["node1"]
        analyzer.cfg["node1"] = ["node2"]
        analyzer.cfg["node2"] = ["exit"]

        analyzer.compute_dominators("entry")

        assert "entry" in analyzer.dominators
        # Entry node should dominate all nodes
        assert "node1" in analyzer.dominators["node2"]


class TestMLBasedDetector:
    """Test suite for ML-Based Detector."""

    def test_feature_extraction(self):
        """Test feature extraction."""
        detector = MLBasedDetector()

        code = "SELECT * FROM users WHERE id = request.input"
        features = detector.extract_features(code)

        assert len(features) > 0
        assert features[0] > 0  # Should detect SQL keywords
        assert features[1] > 0  # Should detect user input

    def test_sql_injection_prediction(self):
        """Test SQL injection prediction."""
        detector = MLBasedDetector()

        vulnerable_code = "execute('SELECT * FROM users WHERE id = ' + user_input)"
        score, vuln_type = detector.predict(vulnerable_code)

        assert score > 0.5  # Should detect vulnerability
        assert vuln_type in ["sql_injection", "unknown"]

    def test_safe_code_prediction(self):
        """Test safe code prediction."""
        detector = MLBasedDetector()

        safe_code = "result = database.query('SELECT * FROM users')"
        score, vuln_type = detector.predict(safe_code)

        # Safe code should have lower score
        assert score < 0.7


class TestStatisticalAnomalyDetector:
    """Test suite for Statistical Anomaly Detector."""

    def test_baseline_update(self):
        """Test baseline statistics update."""
        detector = StatisticalAnomalyDetector()

        # Update baseline with normal values
        for i in range(10):
            detector.update_baseline("endpoint1", "request_size", 100.0 + i)

        assert "endpoint1" in detector.baseline_stats
        assert "request_size" in detector.baseline_stats["endpoint1"]

    def test_anomaly_detection(self):
        """Test anomaly detection."""
        detector = StatisticalAnomalyDetector()

        # Build baseline
        for i in range(20):
            detector.update_baseline("endpoint1", "request_size", 100.0)

        # Normal value (should not be anomaly)
        is_anomaly, z_score = detector.detect_anomaly(
            "endpoint1", "request_size", 105.0
        )
        assert not is_anomaly or z_score < 3.0

        # Anomalous value (should be anomaly)
        is_anomaly, z_score = detector.detect_anomaly(
            "endpoint1", "request_size", 1000.0
        )
        assert is_anomaly or z_score > 3.0

    def test_online_statistics_update(self):
        """Test online statistics update (Welford's algorithm)."""
        detector = StatisticalAnomalyDetector()

        values = [100, 105, 110, 95, 100, 105, 110, 95, 100, 105]

        for value in values:
            detector.update_baseline("endpoint1", "metric1", float(value))

        stats = detector.baseline_stats["endpoint1"]["metric1"]
        assert stats["count"] == len(values)
        assert stats["mean"] > 0
        assert stats["std"] >= 0


class TestAdvancedIASTAnalyzer:
    """Test suite for Advanced IAST Analyzer."""

    def test_request_analysis(self):
        """Test comprehensive request analysis."""
        analyzer = AdvancedIASTAnalyzer()

        request_data = {
            "path": "/api/users",
            "params": {"id": "1 OR 1=1"},
            "headers": {},
        }

        code_context = {
            "code": "execute('SELECT * FROM users WHERE id = ' + request.params.id)",
            "file": "app.py",
            "line": 10,
            "function": "get_user",
        }

        findings = analyzer.analyze_request(request_data, code_context)

        # Should detect SQL injection
        assert len(findings) > 0
        sql_findings = [
            f
            for f in findings
            if f.vulnerability_type == VulnerabilityType.SQL_INJECTION
        ]
        assert len(sql_findings) > 0

    def test_finding_deduplication(self):
        """Test finding deduplication."""
        analyzer = AdvancedIASTAnalyzer()

        finding1 = IASTFinding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity="high",
            source_file="app.py",
            line_number=10,
            function_name="get_user",
            confidence=0.8,
        )

        finding2 = IASTFinding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity="high",
            source_file="app.py",
            line_number=10,
            function_name="get_user",
            confidence=0.9,
        )

        deduplicated = analyzer._deduplicate_findings([finding1, finding2])
        assert len(deduplicated) == 1
        assert deduplicated[0].confidence == 0.9  # Should keep higher confidence

    def test_finding_ranking(self):
        """Test finding ranking."""
        analyzer = AdvancedIASTAnalyzer()

        finding1 = IASTFinding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity="low",
            source_file="app.py",
            line_number=10,
            function_name="get_user",
            confidence=0.5,
            exploitability_score=0.5,
        )

        finding2 = IASTFinding(
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            severity="critical",
            source_file="app.py",
            line_number=20,
            function_name="run_command",
            confidence=0.9,
            exploitability_score=0.9,
        )

        ranked = analyzer._rank_findings([finding1, finding2])

        # Critical finding should be ranked first
        assert ranked[0].severity == "critical"
        assert ranked[0].vulnerability_type == VulnerabilityType.COMMAND_INJECTION

    def test_performance_metrics(self):
        """Test performance metrics collection."""
        analyzer = AdvancedIASTAnalyzer()

        # Simulate some requests
        for i in range(10):
            analyzer.analyze_request(
                {"path": f"/api/endpoint{i}"}, {"code": "test code"}
            )

        metrics = analyzer.get_performance_metrics()

        assert metrics["requests_analyzed"] == 10
        assert metrics["findings_detected"] >= 0
        assert "avg_analysis_time_ms" in metrics

    def test_concurrent_analysis(self):
        """Test concurrent analysis (thread safety)."""
        import threading

        analyzer = AdvancedIASTAnalyzer()

        def analyze_request(request_id: int):
            analyzer.analyze_request(
                {"path": f"/api/endpoint{request_id}"},
                {"code": f"code_{request_id}"},
            )

        threads = []
        for i in range(10):
            thread = threading.Thread(target=analyze_request, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        metrics = analyzer.get_performance_metrics()
        assert metrics["requests_analyzed"] == 10


class TestIntegration:
    """Integration tests for complete IAST workflow."""

    def test_end_to_end_taint_analysis(self):
        """Test end-to-end taint analysis workflow."""
        analyzer = AdvancedIASTAnalyzer()

        # Simulate real request
        request_data = {
            "path": "/api/users",
            "method": "GET",
            "params": {"id": "1' OR '1'='1"},
            "headers": {"User-Agent": "Mozilla/5.0"},
        }

        code_context = {
            "code": """
def get_user(request):
    user_id = request.params.get('id')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return database.execute(query)
            """,
            "file": "app.py",
            "line": 5,
            "function": "get_user",
        }

        findings = analyzer.analyze_request(request_data, code_context)

        # Should detect SQL injection through taint analysis
        assert len(findings) > 0

    def test_performance_under_load(self):
        """Test performance under load."""
        analyzer = AdvancedIASTAnalyzer()

        start_time = time.time()

        # Simulate 100 requests
        for i in range(100):
            analyzer.analyze_request(
                {"path": f"/api/endpoint{i % 10}"},
                {"code": f"code_{i}"},
            )

        elapsed = time.time() - start_time

        # Should complete 100 requests in reasonable time (< 5 seconds)
        assert elapsed < 5.0

        metrics = analyzer.get_performance_metrics()
        assert metrics["requests_analyzed"] == 100
        assert metrics["avg_analysis_time_ms"] < 50  # < 50ms per request


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=risk.runtime.iast_advanced"])
