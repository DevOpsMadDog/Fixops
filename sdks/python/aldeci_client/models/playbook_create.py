from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PlaybookCreate")


@_attrs_define
class PlaybookCreate:
    """
    Attributes:
        org_id (str):
        playbook_name (str):
        trigger_type (str | Unset):  Default: 'manual'.
        steps (list[Any] | Unset):
        estimated_mins (int | Unset):  Default: 60.
    """

    org_id: str
    playbook_name: str
    trigger_type: str | Unset = "manual"
    steps: list[Any] | Unset = UNSET
    estimated_mins: int | Unset = 60
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        playbook_name = self.playbook_name

        trigger_type = self.trigger_type

        steps: list[Any] | Unset = UNSET
        if not isinstance(self.steps, Unset):
            steps = self.steps

        estimated_mins = self.estimated_mins

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "playbook_name": playbook_name,
            }
        )
        if trigger_type is not UNSET:
            field_dict["trigger_type"] = trigger_type
        if steps is not UNSET:
            field_dict["steps"] = steps
        if estimated_mins is not UNSET:
            field_dict["estimated_mins"] = estimated_mins

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        playbook_name = d.pop("playbook_name")

        trigger_type = d.pop("trigger_type", UNSET)

        steps = cast(list[Any], d.pop("steps", UNSET))

        estimated_mins = d.pop("estimated_mins", UNSET)

        playbook_create = cls(
            org_id=org_id,
            playbook_name=playbook_name,
            trigger_type=trigger_type,
            steps=steps,
            estimated_mins=estimated_mins,
        )

        playbook_create.additional_properties = d
        return playbook_create

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
