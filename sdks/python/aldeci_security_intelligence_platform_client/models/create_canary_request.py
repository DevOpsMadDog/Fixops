from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.canary_type import CanaryType
from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateCanaryRequest")


@_attrs_define
class CreateCanaryRequest:
    """
    Attributes:
        type_ (CanaryType): Types of canary / honeypot deception assets.
        description (str): Human-readable description
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    type_: CanaryType
    description: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_.value

        description = self.description

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "description": description,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = CanaryType(d.pop("type"))

        description = d.pop("description")

        org_id = d.pop("org_id", UNSET)

        create_canary_request = cls(
            type_=type_,
            description=description,
            org_id=org_id,
        )

        create_canary_request.additional_properties = d
        return create_canary_request

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
