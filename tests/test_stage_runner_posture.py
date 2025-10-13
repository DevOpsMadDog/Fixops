from types import SimpleNamespace

import pytest

from core.stage_runner import StageRunner


@pytest.fixture()
def runner() -> StageRunner:
    return StageRunner(SimpleNamespace(), SimpleNamespace(), SimpleNamespace())


def test_analyse_posture_detects_open_security_groups(runner: StageRunner) -> None:
    payload = {
        "resources": [
            {
                "type": "aws_security_group",
                "name": "sg-web",
                "changes": {
                    "after": {
                        "ingress": [
                            {"cidr_blocks": ["0.0.0.0/0"]},
                            {"ipv6_cidr_blocks": ["::/0"]},
                        ]
                    }
                },
            },
            {
                "type": "aws_security_group_rule",
                "name": "sg-rule",
                "changes": {
                    "after": {
                        "cidr_blocks": ["10.0.0.0/16"],
                        "ipv6_cidr_blocks": ["::/0"],
                    }
                },
            },
            {
                "type": "aws_security_group_rule",
                "name": "sg-rule-after-empty",
                "cidr_blocks": ["0.0.0.0/0"],
            },
        ]
    }

    posture = runner._analyse_posture(payload)

    assert sorted(posture["open_security_groups"]) == [
        "sg-rule",
        "sg-rule-after-empty",
        "sg-web",
    ]
