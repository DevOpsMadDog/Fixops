import csv
import re
from pathlib import Path

from ssvc.plugins import deployer

import ssvc
from core import DesignContextInjector

FIXTURE = Path(__file__).parent / "fixtures" / "design_context.csv"


def _code(member):
    token = member.name if hasattr(member, "name") else str(member)
    token = token.replace("-", "_").split("_")[0]
    return token[:1].upper()


def test_calculate_priors_matches_ssvc_outcomes():
    injector = DesignContextInjector(methodology="deployer", id_column="control_id")
    priors = injector.calculate_priors(FIXTURE)

    assert [prior.context_id for prior in priors] == [
        "control-1",
        "control-2",
        "control-3",
    ]

    expected_weights = {
        "low": 0.25,
        "medium": 0.55,
        "high": 0.8,
        "immediate": 0.95,
    }

    with FIXTURE.open(encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row, prior in zip(reader, priors):
            decision = ssvc.Decision(
                "deployer",
                exploitation=deployer.ExploitationStatus[row["exploitation"]],
                system_exposure=deployer.SystemExposureLevel[row["system_exposure"]],
                utility=deployer.UtilityLevel[row["utility"]],
                human_impact=deployer.HumanImpactLevel[row["human_impact"]],
            )
            outcome = decision.evaluate()
            assert prior.probability == expected_weights[outcome.priority.value]

            # Ensure rationales incorporate SSVC decision data.
            assert f"SSVC action: {outcome.action.value}" in prior.rationale
            assert f"SSVC priority: {outcome.priority.value}" in prior.rationale

            vector_entry = next(
                item for item in prior.rationale if item.startswith("SSVC vector: ")
            )
            vector_string = vector_entry.split(": ", 1)[1]
            assert vector_string.startswith("DEPLOYERv1/")
            assert vector_string.endswith("/")
            parts = {
                key: value
                for key, value in (
                    segment.split(":", 1)
                    for segment in vector_string.split("/")
                    if ":" in segment
                )
            }
            instance = decision._decision_instance
            assert parts["E"] == _code(instance.exploitation)
            assert parts["SE"] == _code(instance.system_exposure)
            assert parts["U"] == _code(instance.utility)
            assert parts["HI"] == _code(instance.human_impact)

            # Timestamp validation
            timestamp_match = re.search(r"/([0-9]{4}-[0-9T:.-]+)(?:/)?$", vector_string)
            assert timestamp_match, "Vector string must contain an ISO timestamp"
