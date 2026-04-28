from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FromTemplateRequest")


@_attrs_define
class FromTemplateRequest:
    """
    Attributes:
        template_id (str):
        name (str):
        owner_email (str | Unset):  Default: 'unknown'.
        org_id (str | Unset):  Default: 'default'.
    """

    template_id: str
    name: str
    owner_email: str | Unset = "unknown"
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        template_id = self.template_id

        name = self.name

        owner_email = self.owner_email

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "template_id": template_id,
                "name": name,
            }
        )
        if owner_email is not UNSET:
            field_dict["owner_email"] = owner_email
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        template_id = d.pop("template_id")

        name = d.pop("name")

        owner_email = d.pop("owner_email", UNSET)

        org_id = d.pop("org_id", UNSET)

        from_template_request = cls(
            template_id=template_id,
            name=name,
            owner_email=owner_email,
            org_id=org_id,
        )

        from_template_request.additional_properties = d
        return from_template_request

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
