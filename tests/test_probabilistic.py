from fixops.probabilistic import ProbabilisticForecastEngine


def test_probabilistic_engine_generates_posterior_and_forecast() -> None:
    engine = ProbabilisticForecastEngine(
        {
            "bayesian_prior": {"low": 0.2, "medium": 0.6, "high": 1.2, "critical": 1.6},
            "markov_transitions": {
                "medium": {"medium": 0.5, "high": 0.4, "critical": 0.1},
                "high": {"high": 0.4, "critical": 0.5, "medium": 0.1},
            },
            "component_limit": 2,
        }
    )

    severity_counts = {"medium": 3, "high": 2}
    crosswalk = [
        {
            "design_row": {"component": "payments"},
            "findings": [{"level": "error"}],
            "cves": [{"severity": "high"}],
        },
        {
            "design_row": {"component": "notifications"},
            "findings": [{"level": "warning"}],
            "cves": [],
        },
    ]
    exploited_records = [{"cve_id": "CVE-1", "exploited": True}]

    payload = engine.evaluate(severity_counts, crosswalk, exploited_records)

    assert set(payload.keys()) == {"posterior", "next_state", "metrics", "components", "notes"}
    assert abs(sum(payload["posterior"].values()) - 1.0) < 1e-4
    assert any(component["name"] == "payments" for component in payload["components"])
    assert payload["metrics"]["expected_high_or_critical"] >= 0.0
    assert payload["metrics"]["exploited_records"] == 1
    assert payload["notes"]


def test_probabilistic_engine_respects_component_limit() -> None:
    engine = ProbabilisticForecastEngine({"component_limit": 1})

    crosswalk = [
        {"design_row": {"component": "a"}, "findings": [{"level": "error"}], "cves": []},
        {"design_row": {"component": "b"}, "findings": [], "cves": [{"severity": "critical"}]},
    ]

    payload = engine.evaluate({"high": 1}, crosswalk, [])
    assert len(payload["components"]) == 1
