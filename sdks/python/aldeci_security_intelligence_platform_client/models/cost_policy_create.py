from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CostPolicyCreate")


@_attrs_define
class CostPolicyCreate:
    """
    Attributes:
        name (str):
        org_id (str | Unset):  Default: 'default'.
        max_monthly_usd (float | Unset):  Default: 0.0.
        resource_type (str | Unset):  Default: ''.
        action (str | Unset):  Default: 'alert'.
    """

    name: str
    org_id: str | Unset = "default"
    max_monthly_usd: float | Unset = 0.0
    resource_type: str | Unset = ""
    action: str | Unset = "alert"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        org_id = self.org_id

        max_monthly_usd = self.max_monthly_usd

        resource_type = self.resource_type

        action = self.action

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if max_monthly_usd is not UNSET:
            field_dict["max_monthly_usd"] = max_monthly_usd
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if action is not UNSET:
            field_dict["action"] = action

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        org_id = d.pop("org_id", UNSET)

        max_monthly_usd = d.pop("max_monthly_usd", UNSET)

        resource_type = d.pop("resource_type", UNSET)

        action = d.pop("action", UNSET)

        cost_policy_create = cls(
            name=name,
            org_id=org_id,
            max_monthly_usd=max_monthly_usd,
            resource_type=resource_type,
            action=action,
        )

        cost_policy_create.additional_properties = d
        return cost_policy_create

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
