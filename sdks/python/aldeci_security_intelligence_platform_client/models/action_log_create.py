from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ActionLogCreate")


@_attrs_define
class ActionLogCreate:
    """
    Attributes:
        action_name (str):
        action_id (str | Unset):  Default: ''.
        executed_by (str | Unset):  Default: ''.
    """

    action_name: str
    action_id: str | Unset = ""
    executed_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action_name = self.action_name

        action_id = self.action_id

        executed_by = self.executed_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "action_name": action_name,
            }
        )
        if action_id is not UNSET:
            field_dict["action_id"] = action_id
        if executed_by is not UNSET:
            field_dict["executed_by"] = executed_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        action_name = d.pop("action_name")

        action_id = d.pop("action_id", UNSET)

        executed_by = d.pop("executed_by", UNSET)

        action_log_create = cls(
            action_name=action_name,
            action_id=action_id,
            executed_by=executed_by,
        )

        action_log_create.additional_properties = d
        return action_log_create

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
