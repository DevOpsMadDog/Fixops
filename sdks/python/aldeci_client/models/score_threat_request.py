from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ScoreThreatRequest")


@_attrs_define
class ScoreThreatRequest:
    """
    Attributes:
        damage (int):
        reproducibility (int):
        exploitability (int):
        affected_users (int):
        discoverability (int):
    """

    damage: int
    reproducibility: int
    exploitability: int
    affected_users: int
    discoverability: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        damage = self.damage

        reproducibility = self.reproducibility

        exploitability = self.exploitability

        affected_users = self.affected_users

        discoverability = self.discoverability

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "damage": damage,
                "reproducibility": reproducibility,
                "exploitability": exploitability,
                "affected_users": affected_users,
                "discoverability": discoverability,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        damage = d.pop("damage")

        reproducibility = d.pop("reproducibility")

        exploitability = d.pop("exploitability")

        affected_users = d.pop("affected_users")

        discoverability = d.pop("discoverability")

        score_threat_request = cls(
            damage=damage,
            reproducibility=reproducibility,
            exploitability=exploitability,
            affected_users=affected_users,
            discoverability=discoverability,
        )

        score_threat_request.additional_properties = d
        return score_threat_request

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
