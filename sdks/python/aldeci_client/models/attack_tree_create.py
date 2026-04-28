from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AttackTreeCreate")


@_attrs_define
class AttackTreeCreate:
    """
    Attributes:
        root_goal (str): Root attack goal
        attack_vector (str): Attack vector
        likelihood (str | Unset): critical/high/medium/low Default: 'medium'.
        impact (str | Unset): critical/high/medium/low Default: 'medium'.
        path_steps (list[str] | Unset): Attack path steps
    """

    root_goal: str
    attack_vector: str
    likelihood: str | Unset = "medium"
    impact: str | Unset = "medium"
    path_steps: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        root_goal = self.root_goal

        attack_vector = self.attack_vector

        likelihood = self.likelihood

        impact = self.impact

        path_steps: list[str] | Unset = UNSET
        if not isinstance(self.path_steps, Unset):
            path_steps = self.path_steps

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "root_goal": root_goal,
                "attack_vector": attack_vector,
            }
        )
        if likelihood is not UNSET:
            field_dict["likelihood"] = likelihood
        if impact is not UNSET:
            field_dict["impact"] = impact
        if path_steps is not UNSET:
            field_dict["path_steps"] = path_steps

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        root_goal = d.pop("root_goal")

        attack_vector = d.pop("attack_vector")

        likelihood = d.pop("likelihood", UNSET)

        impact = d.pop("impact", UNSET)

        path_steps = cast(list[str], d.pop("path_steps", UNSET))

        attack_tree_create = cls(
            root_goal=root_goal,
            attack_vector=attack_vector,
            likelihood=likelihood,
            impact=impact,
            path_steps=path_steps,
        )

        attack_tree_create.additional_properties = d
        return attack_tree_create

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
