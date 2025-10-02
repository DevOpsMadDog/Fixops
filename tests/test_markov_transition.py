import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "fixops-blended-enterprise"))

from src.services.processing_layer import MarkovState, MarkovTransitionBuilder  # noqa: E402


def _build_state(state: str, epss: float, kev: bool, disclosure_offset_days: int, reference_time: datetime) -> MarkovState:
    return MarkovState(
        current_state=state,
        cve_id=f"{state}-cve",
        epss_score=epss,
        kev_flag=kev,
        disclosure_date=reference_time - timedelta(days=disclosure_offset_days),
    )


def test_transition_matrix_for_vulnerable_states_matches_derived_row():
    reference_time = datetime(2024, 6, 1, tzinfo=timezone.utc)
    builder = MarkovTransitionBuilder()

    states = [
        _build_state("vulnerable", 0.8, True, 10, reference_time),
        _build_state("vulnerable", 0.6, False, 20, reference_time),
    ]

    matrix = builder.build(states, reference_time=reference_time)
    vulnerable_idx = builder.state_to_index["vulnerable"]

    state_metrics = builder._aggregate_metrics(  # pylint: disable=protected-access
        [
            (0.8, 10.0, 1.0),
            (0.6, 20.0, 0.0),
        ],
        builder._state_defaults["vulnerable"],  # pylint: disable=protected-access
    )
    global_metrics = builder._aggregate_metrics(  # pylint: disable=protected-access
        [
            (0.8, 10.0, 1.0),
            (0.6, 20.0, 0.0),
        ],
        builder._global_defaults,  # pylint: disable=protected-access
    )
    expected_row = builder._construct_row("vulnerable", state_metrics, global_metrics)  # pylint: disable=protected-access

    np.testing.assert_allclose(matrix[vulnerable_idx], expected_row, atol=1e-8)
    np.testing.assert_allclose(matrix.sum(axis=1), np.ones(len(builder.states)), atol=1e-8)


def test_patched_state_reflects_low_regression_pressure():
    reference_time = datetime(2024, 6, 1, tzinfo=timezone.utc)
    builder = MarkovTransitionBuilder()

    states = [
        _build_state("patched", 0.15, False, 120, reference_time),
        _build_state("patched", 0.2, False, 90, reference_time),
    ]

    matrix = builder.build(states, reference_time=reference_time)
    patched_idx = builder.state_to_index["patched"]

    state_metrics = builder._aggregate_metrics(  # pylint: disable=protected-access
        [
            (0.15, 120.0, 0.0),
            (0.2, 90.0, 0.0),
        ],
        builder._state_defaults["patched"],  # pylint: disable=protected-access
    )
    global_metrics = builder._aggregate_metrics(  # pylint: disable=protected-access
        [
            (0.15, 120.0, 0.0),
            (0.2, 90.0, 0.0),
        ],
        builder._global_defaults,  # pylint: disable=protected-access
    )
    expected_row = builder._construct_row("patched", state_metrics, global_metrics)  # pylint: disable=protected-access

    np.testing.assert_allclose(matrix[patched_idx], expected_row, atol=1e-8)
    assert matrix[patched_idx][builder.state_to_index["secure"]] > matrix[patched_idx][builder.state_to_index["vulnerable"]]


def test_predict_state_evolution_exposes_transition_matrix():
    reference_time = datetime(2024, 6, 1, tzinfo=timezone.utc)
    builder = MarkovTransitionBuilder()
    states = [
        _build_state("vulnerable", 0.9, True, 5, reference_time),
        _build_state("patched", 0.2, False, 60, reference_time),
    ]

    result = asyncio.run(
        builder.predict_state_evolution(states, reference_time=reference_time)
    )

    assert "transition_matrix" in result and result["transition_matrix"]
    assert result.get("state_labels") == builder.states
    np.testing.assert_allclose(np.array(result["transition_matrix"]), builder.transition_matrix)
    assert any(
        prediction["predicted_transitions"].get("exploited", 0) > 0.3
        for prediction in result["predictions"]
        if prediction["current_state"] == "vulnerable"
    )
