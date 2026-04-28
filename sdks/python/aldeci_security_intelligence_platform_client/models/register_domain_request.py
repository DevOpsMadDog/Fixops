from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterDomainRequest")


@_attrs_define
class RegisterDomainRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        domain_name (str): Name of the maturity domain
        domain_type (str | Unset): Domain category Default: 'governance'.
        target_level (int | Unset): Target maturity level (1-5) Default: 3.
    """

    org_id: str
    domain_name: str
    domain_type: str | Unset = "governance"
    target_level: int | Unset = 3
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        domain_name = self.domain_name

        domain_type = self.domain_type

        target_level = self.target_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "domain_name": domain_name,
            }
        )
        if domain_type is not UNSET:
            field_dict["domain_type"] = domain_type
        if target_level is not UNSET:
            field_dict["target_level"] = target_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        domain_name = d.pop("domain_name")

        domain_type = d.pop("domain_type", UNSET)

        target_level = d.pop("target_level", UNSET)

        register_domain_request = cls(
            org_id=org_id,
            domain_name=domain_name,
            domain_type=domain_type,
            target_level=target_level,
        )

        register_domain_request.additional_properties = d
        return register_domain_request

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
