from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreatePlaybookIn")


@_attrs_define
class CreatePlaybookIn:
    """
    Attributes:
        playbook_name (str): Playbook name
        steps (list[Any] | Unset): Ordered list of playbook steps
        target_type (str | Unset): host|container|network|identity|application|cloud_resource Default: 'host'.
        estimated_duration_minutes (int | Unset): Estimated run time in minutes Default: 0.
    """

    playbook_name: str
    steps: list[Any] | Unset = UNSET
    target_type: str | Unset = "host"
    estimated_duration_minutes: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        playbook_name = self.playbook_name

        steps: list[Any] | Unset = UNSET
        if not isinstance(self.steps, Unset):
            steps = self.steps

        target_type = self.target_type

        estimated_duration_minutes = self.estimated_duration_minutes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "playbook_name": playbook_name,
            }
        )
        if steps is not UNSET:
            field_dict["steps"] = steps
        if target_type is not UNSET:
            field_dict["target_type"] = target_type
        if estimated_duration_minutes is not UNSET:
            field_dict["estimated_duration_minutes"] = estimated_duration_minutes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        playbook_name = d.pop("playbook_name")

        steps = cast(list[Any], d.pop("steps", UNSET))

        target_type = d.pop("target_type", UNSET)

        estimated_duration_minutes = d.pop("estimated_duration_minutes", UNSET)

        create_playbook_in = cls(
            playbook_name=playbook_name,
            steps=steps,
            target_type=target_type,
            estimated_duration_minutes=estimated_duration_minutes,
        )

        create_playbook_in.additional_properties = d
        return create_playbook_in

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
