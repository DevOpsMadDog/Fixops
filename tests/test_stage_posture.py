import pytest

from core.stage_runner import StageRunner


class _Dummy:
    def __getattr__(self, name):  # pragma: no cover - defensive default for unused services
        raise AttributeError(name)


def _make_runner() -> StageRunner:
    return StageRunner(registry=_Dummy(), allocator=_Dummy(), signer=_Dummy())


def test_analyse_posture_flags_open_security_groups_ipv4_and_ipv6() -> None:
    runner = _make_runner()
    payload = {
        "resources": [
            {
                "type": "aws_security_group",
                "name": "web",
                "changes": {
                    "after": {
                        "ingress": [
                            {
                                "cidr_blocks": ["0.0.0.0/0"],
                                "description": "allow all",
                            }
                        ]
                    }
                },
            },
            {
                "type": "aws_security_group_rule",
                "name": "db_ipv6",
                "changes": {
                    "after": {
                        "cidr_blocks": [],
                        "ipv6_cidr_blocks": ["::/0"],
                    }
                },
            },
        ]
    }

    posture = runner._analyse_posture(payload)

    assert sorted(posture["open_security_groups"]) == ["db_ipv6", "web"]


def test_load_deploy_payload_rejects_malformed_yaml() -> None:
    runner = _make_runner()

    with pytest.raises(ValueError):
        runner._load_deploy_payload(b"resources:\n - name: web\n invalid")
