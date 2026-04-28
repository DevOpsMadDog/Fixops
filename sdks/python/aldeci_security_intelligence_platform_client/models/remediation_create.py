from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RemediationCreate")


@_attrs_define
class RemediationCreate:
    """
    Attributes:
        finding (str):
        remediation_action (str):
        priority (str | Unset):  Default: 'medium'.
    """

    finding: str
    remediation_action: str
    priority: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding = self.finding

        remediation_action = self.remediation_action

        priority = self.priority

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding": finding,
                "remediation_action": remediation_action,
            }
        )
        if priority is not UNSET:
            field_dict["priority"] = priority

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding = d.pop("finding")

        remediation_action = d.pop("remediation_action")

        priority = d.pop("priority", UNSET)

        remediation_create = cls(
            finding=finding,
            remediation_action=remediation_action,
            priority=priority,
        )

        remediation_create.additional_properties = d
        return remediation_create

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
