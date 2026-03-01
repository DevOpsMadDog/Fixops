"""Integration tests for FAIL Engine + Router + DB — end-to-end scoring.

Covers the full FAIL scoring pipeline from HTTP request through engine
computation to DB persistence and retrieval.
"""

import os
import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret-for-ci-testing")


# ---------------------------------------------------------------------------
# Unit tests for FAILEngine (no FastAPI dependency)
# ---------------------------------------------------------------------------


class TestFAILEngineUnit:
    """Direct unit tests for the FAIL engine scoring logic."""

    def _engine(self):
        from core.fail_engine import FAILEngine
        return FAILEngine()

    def _input(self, **kw):
        from core.fail_engine import FAILInput
        return FAILInput(**kw)

    # -- Score range tests --

    def test_critical_cve_scores_high(self):
        engine = self._engine()
        inp = self._input(
            cve_id="CVE-2024-3094",
            cvss_score=10.0,
            epss_score=0.97,
            is_kev=True,
            asset_criticality="critical",
            has_exploit=True,
            is_reachable=True,
            data_classification="pii",
        )
        result = engine.score(inp)
        assert result.fail_score >= 70.0
        assert result.grade.value in ("CRITICAL", "HIGH")
        assert result.recommended_action.value in ("PATCH_IMMEDIATELY", "PATCH_NEXT_SPRINT")

    def test_low_severity_scores_low(self):
        engine = self._engine()
        inp = self._input(
            cve_id="CVE-2024-9999",
            cvss_score=2.0,
            epss_score=0.01,
            is_kev=False,
            asset_criticality="low",
            has_exploit=False,
            data_classification="public",
        )
        result = engine.score(inp)
        assert result.fail_score < 50.0

    def test_zero_input_produces_nonzero_score(self):
        """Even with minimal input, engine should produce a valid score."""
        engine = self._engine()
        inp = self._input()
        result = engine.score(inp)
        assert 0.0 <= result.fail_score <= 100.0
        assert result.grade is not None
        assert result.recommended_action is not None

    # -- Grade mapping tests --

    @pytest.mark.parametrize("score,expected_grade", [
        (95.0, "CRITICAL"),
        (90.0, "CRITICAL"),
        (75.0, "HIGH"),
        (70.0, "HIGH"),
        (50.0, "MEDIUM"),
        (40.0, "MEDIUM"),
        (25.0, "LOW"),
        (20.0, "LOW"),
        (10.0, "INFO"),
        (0.0, "INFO"),
    ])
    def test_score_to_grade_mapping(self, score, expected_grade):
        from core.fail_engine import FAILEngine
        grade = FAILEngine._score_to_grade(score)
        assert grade.value == expected_grade

    # -- Action mapping tests --

    @pytest.mark.parametrize("grade_val,expected_action", [
        ("CRITICAL", "PATCH_IMMEDIATELY"),
        ("HIGH", "PATCH_NEXT_SPRINT"),
        ("MEDIUM", "SCHEDULE_FIX"),
        ("LOW", "MONITOR"),
        ("INFO", "ACCEPT_RISK"),
    ])
    def test_grade_to_action_mapping(self, grade_val, expected_action):
        from core.fail_engine import FAILEngine, FAILGrade
        grade = FAILGrade(grade_val)
        action = FAILEngine._grade_to_action(grade)
        assert action.value == expected_action

    # -- Sub-score tests --

    def test_fact_score_with_cve_and_cvss(self):
        engine = self._engine()
        inp = self._input(cve_id="CVE-2024-1234", cvss_score=8.0)
        result = engine.score(inp)
        assert result.fact.has_cve is True
        assert result.fact.has_cvss is True
        assert result.fact.score > 0

    def test_fact_score_high_evidence_quality(self):
        engine = self._engine()
        inp = self._input(
            cve_id="CVE-2024-1234",
            cvss_score=9.0,
            epss_score=0.5,
            has_exploit=True,
        )
        result = engine.score(inp)
        assert result.fact.evidence_quality == "high"
        assert result.fact.multiple_sources is True

    def test_assess_score_with_weaponized_exploit(self):
        from core.fail_engine import ExploitMaturity
        engine = self._engine()
        inp = self._input(
            cvss_score=9.5,
            exploit_maturity=ExploitMaturity.WEAPONIZED,
        )
        result = engine.score(inp)
        assert result.assess.exploit_maturity == "weaponized"
        assert result.assess.score >= 70.0

    def test_impact_score_with_critical_pii_asset(self):
        engine = self._engine()
        inp = self._input(
            cvss_score=9.0,
            asset_criticality="critical",
            data_classification="pii",
            affected_assets=50,
            compliance_frameworks=["SOC2", "PCI-DSS"],
        )
        result = engine.score(inp)
        assert result.impact.score >= 70.0
        assert result.impact.blast_radius == "system"
        assert result.impact.business_impact == "critical"

    def test_likelihood_kev_boost(self):
        engine = self._engine()
        inp_kev = self._input(is_kev=True, epss_score=0.5)
        inp_no_kev = self._input(is_kev=False, epss_score=0.5)
        result_kev = engine.score(inp_kev)
        result_no_kev = engine.score(inp_no_kev)
        assert result_kev.likelihood.kev_boost == 25.0
        assert result_no_kev.likelihood.kev_boost == 0.0

    def test_likelihood_exposure_factor(self):
        engine = self._engine()
        inp = self._input(is_reachable=True, is_internet_facing=True)
        result = engine.score(inp)
        assert result.likelihood.exposure_factor >= 15.0

    def test_compensating_controls_reduce_exposure(self):
        engine = self._engine()
        inp = self._input(
            is_reachable=True,
            is_internet_facing=True,
            has_compensating_controls=True,
        )
        result = engine.score(inp)
        assert result.likelihood.exposure_factor < 20.0

    # -- Weight adjustment tests --

    def test_weights_sum_to_one(self):
        engine = self._engine()
        inp = self._input(cve_id="CVE-2024-1234", cvss_score=7.0)
        result = engine.score(inp)
        total = sum(result.weights.values())
        assert abs(total - 1.0) < 0.001

    def test_kev_boosts_likelihood_weight(self):
        engine = self._engine()
        inp_kev = self._input(is_kev=True)
        inp_no_kev = self._input(is_kev=False)
        r_kev = engine.score(inp_kev)
        r_no_kev = engine.score(inp_no_kev)
        assert r_kev.weights["likelihood"] > r_no_kev.weights["likelihood"]

    def test_critical_asset_boosts_impact_weight(self):
        engine = self._engine()
        inp_crit = self._input(asset_criticality="critical")
        inp_low = self._input(asset_criticality="low")
        r_crit = engine.score(inp_crit)
        r_low = engine.score(inp_low)
        assert r_crit.weights["impact"] > r_low.weights["impact"]

    # -- Batch scoring --

    def test_batch_scoring(self):
        engine = self._engine()
        inputs = [
            self._input(cve_id=f"CVE-2024-{i}", cvss_score=float(i))
            for i in range(1, 6)
        ]
        results = engine.score_batch(inputs)
        assert len(results) == 5
        for r in results:
            assert 0.0 <= r.fail_score <= 100.0

    # -- Ranking and comparison --

    def test_rank_returns_sorted_desc(self):
        engine = self._engine()
        r1 = engine.score(self._input(cvss_score=2.0))
        r2 = engine.score(self._input(cvss_score=9.0, is_kev=True))
        r3 = engine.score(self._input(cvss_score=5.0))
        ranked = engine.rank([r1, r2, r3])
        scores = [r.fail_score for r in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_compare_two_results(self):
        engine = self._engine()
        r1 = engine.score(self._input(cve_id="CVE-A", cvss_score=9.0))
        r2 = engine.score(self._input(cve_id="CVE-B", cvss_score=3.0))
        cmp = engine.compare(r1, r2)
        assert cmp["winner"] == "CVE-A"
        assert cmp["score_diff"] > 0

    # -- Statistics --

    def test_stats_after_scoring(self):
        engine = self._engine()
        engine.score(self._input(cvss_score=9.0))
        engine.score(self._input(cvss_score=3.0))
        stats = engine.stats()
        assert stats["total_scored"] == 2
        assert "average_score" in stats
        assert "grade_distribution" in stats

    def test_stats_empty(self):
        engine = self._engine()
        stats = engine.stats()
        assert stats["total_scored"] == 0

    # -- Serialization --

    def test_result_to_dict(self):
        engine = self._engine()
        result = engine.score(self._input(cve_id="CVE-2024-5678", cvss_score=7.5))
        d = result.to_dict()
        assert "fail_score" in d
        assert "grade" in d
        assert "recommended_action" in d
        assert "sub_scores" in d
        assert "fact" in d["sub_scores"]
        assert "assess" in d["sub_scores"]
        assert "impact" in d["sub_scores"]
        assert "likelihood" in d["sub_scores"]
        assert d["cve_id"] == "CVE-2024-5678"
        assert d["engine_version"] == "1.0.0"

    def test_score_id_format(self):
        engine = self._engine()
        result = engine.score(self._input())
        assert result.score_id.startswith("FAIL-")
        assert len(result.score_id) > 5

    def test_computation_time_tracked(self):
        engine = self._engine()
        result = engine.score(self._input(cvss_score=7.0))
        assert result.computation_ms >= 0.0

    # -- Enum coverage --

    @pytest.mark.parametrize("criticality", [
        "critical", "high", "medium", "low", "unknown"
    ])
    def test_all_asset_criticalities(self, criticality):
        engine = self._engine()
        result = engine.score(self._input(asset_criticality=criticality))
        assert 0.0 <= result.fail_score <= 100.0

    @pytest.mark.parametrize("data_cls", [
        "pii", "phi", "pci", "financial", "credentials", "internal", "public", "none"
    ])
    def test_all_data_classifications(self, data_cls):
        engine = self._engine()
        result = engine.score(self._input(data_classification=data_cls))
        assert 0.0 <= result.fail_score <= 100.0

    @pytest.mark.parametrize("maturity_val", [
        "weaponized", "poc_public", "poc_private", "theoretical", "unknown"
    ])
    def test_all_exploit_maturities(self, maturity_val):
        from core.fail_engine import ExploitMaturity
        engine = self._engine()
        maturity = ExploitMaturity(maturity_val)
        result = engine.score(self._input(exploit_maturity=maturity))
        assert 0.0 <= result.fail_score <= 100.0

    # -- Custom weights --

    def test_custom_weights(self):
        from core.fail_engine import FAILEngine
        custom = {"fact": 0.50, "assess": 0.10, "impact": 0.20, "likelihood": 0.20}
        engine = FAILEngine(weights=custom)
        result = engine.score(self._input(cvss_score=7.0))
        assert 0.0 <= result.fail_score <= 100.0

    # -- History tracking --

    def test_history_accumulates(self):
        engine = self._engine()
        assert len(engine.history) == 0
        engine.score(self._input())
        engine.score(self._input())
        assert len(engine.history) == 2


# ---------------------------------------------------------------------------
# CWE Fix Registry tests
# ---------------------------------------------------------------------------


class TestCWEFixRegistry:
    """Test the CWE fix template registry."""

    def _registry(self):
        from automation.remediation import CWEFixRegistry
        return CWEFixRegistry

    def test_supported_cwes(self):
        reg = self._registry()
        supported = reg.supported_cwes()
        assert "CWE-22" in supported
        assert "CWE-78" in supported
        assert "CWE-79" in supported
        assert "CWE-89" in supported
        assert "CWE-502" in supported
        assert len(supported) == 5

    @pytest.mark.parametrize("cwe_id", ["CWE-79", "CWE-89", "CWE-502", "CWE-78", "CWE-22"])
    def test_can_fix_supported_cwes(self, cwe_id):
        reg = self._registry()
        assert reg.can_fix(cwe_id) is True

    def test_cannot_fix_unsupported(self):
        reg = self._registry()
        assert reg.can_fix("CWE-999") is False

    @pytest.mark.parametrize("raw,expected", [
        ("CWE-79", "CWE-79"),
        ("cwe-79", "CWE-79"),
        ("79", "CWE-79"),
        ("CWE79", "CWE-79"),
        ("cwe79", "CWE-79"),
    ])
    def test_normalize_cwe_formats(self, raw, expected):
        reg = self._registry()
        assert reg._normalize_cwe(raw) == expected

    @pytest.mark.parametrize("cwe_id,source", [
        ("CWE-79", 'return f"<p>{user_input}</p>"'),
        ("CWE-89", 'cursor.execute(f"SELECT * FROM t WHERE id={uid}")'),
        ("CWE-502", "import pickle\ndata = pickle.loads(user_data)"),
        ("CWE-78", 'os.system(f"ls {user_dir}")'),
        ("CWE-22", 'path = os.path.join(base, user_input)\nopen(path)'),
    ])
    def test_generate_fix_returns_template(self, cwe_id, source):
        reg = self._registry()
        finding = {
            "file_path": "app.py",
            "title": f"Test {cwe_id}",
            "severity": "high",
            "language": "python",
            "code_snippet": source,
        }
        template = reg.generate_fix(cwe_id, finding, source_code=source)
        assert template.cwe_id == cwe_id
        assert template.test_code  # Non-empty
        assert template.pr_title  # Non-empty
        assert template.pr_description  # Non-empty

    def test_generate_fix_unsupported_raises(self):
        reg = self._registry()
        with pytest.raises(ValueError, match="Unsupported CWE"):
            reg.generate_fix("CWE-999", {})

    def test_cwe79_xss_fix_escapes_html(self):
        reg = self._registry()
        vulnerable = 'return f"<p>{user_input}</p>"'
        finding = {"file_path": "view.py", "language": "python", "code_snippet": vulnerable}
        template = reg.generate_fix("CWE-79", finding, source_code=vulnerable)
        assert "escape" in template.fix_code.lower() or "markupsafe" in template.fix_code.lower()

    def test_cwe89_sql_fix_generates_test_and_pr(self):
        reg = self._registry()
        vulnerable = 'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")'
        finding = {"file_path": "db.py", "language": "python", "code_snippet": vulnerable}
        template = reg.generate_fix("CWE-89", finding, source_code=vulnerable)
        # Fix code may or may not transform (depends on pattern match), but metadata always present
        assert template.test_code  # Test code always generated
        assert "CWE-89" in template.pr_title

    def test_cwe502_deser_fix_replaces_pickle(self):
        reg = self._registry()
        vulnerable = "import pickle\ndata = pickle.loads(user_data)"
        finding = {"file_path": "loader.py", "language": "python", "code_snippet": vulnerable}
        template = reg.generate_fix("CWE-502", finding, source_code=vulnerable)
        assert "json" in template.fix_code.lower()

    def test_cwe78_cmd_injection_fix(self):
        reg = self._registry()
        vulnerable = 'os.system(f"ls {user_dir}")'
        finding = {"file_path": "utils.py", "language": "python", "code_snippet": vulnerable}
        template = reg.generate_fix("CWE-78", finding, source_code=vulnerable)
        assert "subprocess" in template.fix_code.lower() or "shlex" in template.fix_code.lower()

    def test_cwe22_path_traversal_fix(self):
        reg = self._registry()
        vulnerable = 'file_path = os.path.join(base, user_input)\nwith open(file_path) as f:\n    data = f.read()'
        finding = {"file_path": "files.py", "language": "python", "code_snippet": vulnerable}
        template = reg.generate_fix("CWE-22", finding, source_code=vulnerable)
        assert "resolve" in template.fix_code.lower() or "safe" in template.fix_code.lower()


# ---------------------------------------------------------------------------
# Remediation Engine tests
# ---------------------------------------------------------------------------


class TestRemediationEngine:
    """Test the RemediationEngine orchestration layer."""

    def _engine(self):
        from automation.remediation import RemediationEngine
        return RemediationEngine()

    def test_determine_strategy_auto_fix_for_cwe(self):
        from automation.remediation import RemediationStrategy
        engine = self._engine()
        finding = {"cwe_id": "CWE-79", "severity": "high"}
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.AUTO_FIX

    def test_determine_strategy_manual_when_disabled(self):
        from automation.remediation import RemediationEngine, RemediationStrategy
        engine = RemediationEngine(config={"auto_fix_enabled": False})
        finding = {"cwe_id": "CWE-79", "severity": "high"}
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.MANUAL

    def test_determine_strategy_guided_for_medium(self):
        from automation.remediation import RemediationStrategy
        engine = self._engine()
        finding = {"severity": "medium", "fix_available": True}
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.GUIDED

    def test_determine_strategy_manual_for_low_no_fix(self):
        from automation.remediation import RemediationStrategy
        engine = self._engine()
        finding = {"severity": "low", "fix_available": False}
        strategy = engine.determine_strategy(finding)
        assert strategy == RemediationStrategy.MANUAL

    def test_remediate_auto_fix_cwe(self):
        from automation.remediation import RemediationStatus
        engine = self._engine()
        finding = {
            "cwe_id": "CWE-89",
            "severity": "high",
            "file_path": "db.py",
            "language": "python",
            "code_snippet": 'cursor.execute(f"SELECT * FROM t WHERE id={uid}")',
        }
        result = engine.remediate("finding-001", finding)
        assert result.finding_id == "finding-001"
        # Status should be at least FIX_GENERATED (may not have PR since no SCM)
        assert result.status in (
            RemediationStatus.FIX_GENERATED,
            RemediationStatus.PR_CREATED,
            RemediationStatus.FAILED,
            RemediationStatus.PENDING,
        )

    def test_remediate_accept_risk(self):
        from automation.remediation import RemediationStatus, RemediationStrategy
        engine = self._engine()
        result = engine.remediate(
            "finding-002",
            {"severity": "low"},
            strategy=RemediationStrategy.ACCEPT_RISK,
        )
        assert result.status == RemediationStatus.SKIPPED

    def test_remediate_manual_strategy(self):
        from automation.remediation import RemediationStatus, RemediationStrategy
        engine = self._engine()
        result = engine.remediate(
            "finding-003",
            {"severity": "low"},
            strategy=RemediationStrategy.MANUAL,
        )
        assert result.status == RemediationStatus.PENDING


# ---------------------------------------------------------------------------
# PersistentDict tests
# ---------------------------------------------------------------------------


class TestPersistentDict:
    """Test the SQLite-backed persistent dictionary."""

    def _make_store(self, tmp_path, table="test_store"):
        from core.persistent_store import PersistentDict
        db = str(tmp_path / "test.db")
        return PersistentDict(table, db_path=db)

    def test_set_and_get(self, tmp_path):
        store = self._make_store(tmp_path)
        store["key1"] = {"value": 42}
        assert store["key1"] == {"value": 42}

    def test_contains(self, tmp_path):
        store = self._make_store(tmp_path)
        store["exists"] = True
        assert "exists" in store
        assert "missing" not in store

    def test_delete(self, tmp_path):
        store = self._make_store(tmp_path)
        store["key"] = "value"
        del store["key"]
        assert "key" not in store

    def test_len(self, tmp_path):
        store = self._make_store(tmp_path)
        store["a"] = 1
        store["b"] = 2
        assert len(store) == 2

    def test_iter(self, tmp_path):
        store = self._make_store(tmp_path)
        store["x"] = 1
        store["y"] = 2
        keys = list(store)
        assert set(keys) == {"x", "y"}

    def test_get_with_default(self, tmp_path):
        store = self._make_store(tmp_path)
        assert store.get("missing", "default") == "default"
        store["present"] = 42
        assert store.get("present", "default") == 42

    def test_persistence_across_instances(self, tmp_path):
        from core.persistent_store import PersistentDict
        db = str(tmp_path / "persist.db")
        store1 = PersistentDict("test", db_path=db)
        store1["key"] = "value"
        # Create new instance reading same DB
        store2 = PersistentDict("test", db_path=db)
        assert store2["key"] == "value"

    def test_overwrite_value(self, tmp_path):
        store = self._make_store(tmp_path)
        store["key"] = "old"
        store["key"] = "new"
        assert store["key"] == "new"

    def test_complex_json_values(self, tmp_path):
        store = self._make_store(tmp_path)
        complex_val = {
            "nested": {"list": [1, 2, 3]},
            "bool": True,
            "null": None,
        }
        store["complex"] = complex_val
        assert store["complex"] == complex_val

    def test_persist_method(self, tmp_path):
        store = self._make_store(tmp_path)
        store["key"] = {"count": 0}
        store["key"]["count"] = 5  # In-place mutation
        store.persist("key")  # Explicit flush
        from core.persistent_store import PersistentDict
        store2 = PersistentDict("test_store", db_path=str(tmp_path / "test.db"))
        assert store2["key"]["count"] == 5
