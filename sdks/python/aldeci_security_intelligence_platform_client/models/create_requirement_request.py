from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateRequirementRequest")


@_attrs_define
class CreateRequirementRequest:
    """
    Attributes:
        vendor_id (str): ID of the vendor
        requirement_name (str): Requirement name
        requirement_type (str): One of: documentation, certification, audit, training, technical
        due_date (str): Due date (ISO 8601 or YYYY-MM-DD)
        org_id (str | Unset): Organisation identifier Default: 'default'.
        mandatory (bool | Unset): Whether this requirement is mandatory Default: True.
    """

    vendor_id: str
    requirement_name: str
    requirement_type: str
    due_date: str
    org_id: str | Unset = "default"
    mandatory: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vendor_id = self.vendor_id

        requirement_name = self.requirement_name

        requirement_type = self.requirement_type

        due_date = self.due_date

        org_id = self.org_id

        mandatory = self.mandatory

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor_id": vendor_id,
                "requirement_name": requirement_name,
                "requirement_type": requirement_type,
                "due_date": due_date,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if mandatory is not UNSET:
            field_dict["mandatory"] = mandatory

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vendor_id = d.pop("vendor_id")

        requirement_name = d.pop("requirement_name")

        requirement_type = d.pop("requirement_type")

        due_date = d.pop("due_date")

        org_id = d.pop("org_id", UNSET)

        mandatory = d.pop("mandatory", UNSET)

        create_requirement_request = cls(
            vendor_id=vendor_id,
            requirement_name=requirement_name,
            requirement_type=requirement_type,
            due_date=due_date,
            org_id=org_id,
            mandatory=mandatory,
        )

        create_requirement_request.additional_properties = d
        return create_requirement_request

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
