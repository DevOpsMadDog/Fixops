from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CheckIPRequest")


@_attrs_define
class CheckIPRequest:
    """
    Attributes:
        ip (str): IP address to check
        country_code (str): Country code for the IP
        org_id (str | Unset):  Default: 'default'.
    """

    ip: str
    country_code: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ip = self.ip

        country_code = self.country_code

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ip": ip,
                "country_code": country_code,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ip = d.pop("ip")

        country_code = d.pop("country_code")

        org_id = d.pop("org_id", UNSET)

        check_ip_request = cls(
            ip=ip,
            country_code=country_code,
            org_id=org_id,
        )

        check_ip_request.additional_properties = d
        return check_ip_request

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
