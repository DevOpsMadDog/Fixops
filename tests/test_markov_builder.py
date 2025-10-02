from datetime import date

import numpy as np
import pytest

from new_backend.processing.markov import (
    MarkovState,
    MarkovTransitionBuilder,
    TimelineEvent,
    TimelineEventType,
    VulnerabilityRecord,
)


def build_record(cve_id, epss, kev, events):
    return VulnerabilityRecord(
        cve_id=cve_id,
        epss_score=epss,
        kev=kev,
        timeline=[
            TimelineEvent(occurred=event_date, event_type=event_type)
            for event_date, event_type in events
        ],
    )


def test_transition_matrix_matches_expected_sequences():
    builder = MarkovTransitionBuilder(epss_high_risk_threshold=0.7)
    records = [
        build_record(
            "CVE-2024-0001",
            epss=0.2,
            kev=False,
            events=[
                (date(2024, 1, 1), TimelineEventType.DISCLOSURE),
                (date(2024, 1, 10), TimelineEventType.PATCH_RELEASED),
            ],
        ),
        build_record(
            "CVE-2024-0002",
            epss=0.95,
            kev=False,
            events=[
                (date(2024, 2, 1), TimelineEventType.DISCLOSURE),
                (date(2024, 2, 10), TimelineEventType.EXPLOIT_CONFIRMED),
            ],
        ),
        build_record(
            "CVE-2024-0003",
            epss=0.85,
            kev=True,
            events=[
                (date(2024, 3, 2), TimelineEventType.DISCLOSURE),
                (date(2024, 3, 15), TimelineEventType.PATCH_RELEASED),
            ],
        ),
    ]

    probabilities = builder.build(records)

    expected_matrix = np.array(
        [
            [0.0, 2.0 / 3.0, 0.0, 1.0 / 3.0],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 1.0],
            [0.0, 0.0, 0.0, 1.0],
        ]
    )

    np.testing.assert_allclose(probabilities.transition_matrix, expected_matrix)
    assert list(probabilities.markov_chain.states) == [state.value for state in probabilities.states]
    assert probabilities.probability(MarkovState.DISCLOSED, MarkovState.WEAPONIZED) == pytest.approx(
        2.0 / 3.0
    )
    assert probabilities.probability(MarkovState.WEAPONIZED, MarkovState.EXPLOITED) == pytest.approx(1.0)
