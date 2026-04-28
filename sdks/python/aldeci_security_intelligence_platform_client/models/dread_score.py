from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DREADScore")


@_attrs_define
class DREADScore:
    """DREAD risk scoring model.

    Each dimension rated 1–10 (1 = lowest risk, 10 = highest).
    ``total`` is the arithmetic mean of all five dimensions.

        Attributes:
            damage (int): Damage potential if exploited (1-10)
            reproducibility (int): How easily can the attack be reproduced (1-10)
            exploitability (int): Skill/effort required to exploit (1-10)
            affected_users (int): Number of users affected (1-10)
            discoverability (int): How easy is it to discover the vulnerability (1-10)
            total (float | Unset): Computed mean of all five dimensions Default: 0.0.
    """

    damage: int
    reproducibility: int
    exploitability: int
    affected_users: int
    discoverability: int
    total: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        damage = self.damage

        reproducibility = self.reproducibility

        exploitability = self.exploitability

        affected_users = self.affected_users

        discoverability = self.discoverability

        total = self.total

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
        if total is not UNSET:
            field_dict["total"] = total

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        damage = d.pop("damage")

        reproducibility = d.pop("reproducibility")

        exploitability = d.pop("exploitability")

        affected_users = d.pop("affected_users")

        discoverability = d.pop("discoverability")

        total = d.pop("total", UNSET)

        dread_score = cls(
            damage=damage,
            reproducibility=reproducibility,
            exploitability=exploitability,
            affected_users=affected_users,
            discoverability=discoverability,
            total=total,
        )

        dread_score.additional_properties = d
        return dread_score

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
