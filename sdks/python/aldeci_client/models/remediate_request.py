from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RemediateRequest")


@_attrs_define
class RemediateRequest:
    """
    Attributes:
        remediated_by (str):
        action_taken (str):
    """

    remediated_by: str
    action_taken: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        remediated_by = self.remediated_by

        action_taken = self.action_taken

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "remediated_by": remediated_by,
                "action_taken": action_taken,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        remediated_by = d.pop("remediated_by")

        action_taken = d.pop("action_taken")

        remediate_request = cls(
            remediated_by=remediated_by,
            action_taken=action_taken,
        )

        remediate_request.additional_properties = d
        return remediate_request

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
