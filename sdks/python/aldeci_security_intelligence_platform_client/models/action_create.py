from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ActionCreate")


@_attrs_define
class ActionCreate:
    """
    Attributes:
        action_name (str):
        action_type (str):
        description (str | Unset):  Default: ''.
        automated (bool | Unset):  Default: False.
        timeout_mins (int | Unset):  Default: 30.
    """

    action_name: str
    action_type: str
    description: str | Unset = ""
    automated: bool | Unset = False
    timeout_mins: int | Unset = 30
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action_name = self.action_name

        action_type = self.action_type

        description = self.description

        automated = self.automated

        timeout_mins = self.timeout_mins

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "action_name": action_name,
                "action_type": action_type,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if automated is not UNSET:
            field_dict["automated"] = automated
        if timeout_mins is not UNSET:
            field_dict["timeout_mins"] = timeout_mins

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        action_name = d.pop("action_name")

        action_type = d.pop("action_type")

        description = d.pop("description", UNSET)

        automated = d.pop("automated", UNSET)

        timeout_mins = d.pop("timeout_mins", UNSET)

        action_create = cls(
            action_name=action_name,
            action_type=action_type,
            description=description,
            automated=automated,
            timeout_mins=timeout_mins,
        )

        action_create.additional_properties = d
        return action_create

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
