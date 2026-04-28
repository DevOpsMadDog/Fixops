from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddRemediationPlanRequest")


@_attrs_define
class AddRemediationPlanRequest:
    """
    Attributes:
        org_id (str): Organisation ID
        action (str): Remediation action description
        resource_required (str | Unset): Resources required Default: ''.
        estimated_days (int | Unset): Estimated days to complete Default: 0.
    """

    org_id: str
    action: str
    resource_required: str | Unset = ""
    estimated_days: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        action = self.action

        resource_required = self.resource_required

        estimated_days = self.estimated_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "action": action,
            }
        )
        if resource_required is not UNSET:
            field_dict["resource_required"] = resource_required
        if estimated_days is not UNSET:
            field_dict["estimated_days"] = estimated_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        action = d.pop("action")

        resource_required = d.pop("resource_required", UNSET)

        estimated_days = d.pop("estimated_days", UNSET)

        add_remediation_plan_request = cls(
            org_id=org_id,
            action=action,
            resource_required=resource_required,
            estimated_days=estimated_days,
        )

        add_remediation_plan_request.additional_properties = d
        return add_remediation_plan_request

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
