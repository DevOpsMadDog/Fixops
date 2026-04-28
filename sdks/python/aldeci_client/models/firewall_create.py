from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FirewallCreate")


@_attrs_define
class FirewallCreate:
    """
    Attributes:
        name (str):
        vendor (str | Unset):  Default: 'generic'.
        model (str | Unset):  Default: ''.
        fw_type (str | Unset):  Default: 'perimeter'.
        ip_address (str | Unset):  Default: ''.
    """

    name: str
    vendor: str | Unset = "generic"
    model: str | Unset = ""
    fw_type: str | Unset = "perimeter"
    ip_address: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        vendor = self.vendor

        model = self.model

        fw_type = self.fw_type

        ip_address = self.ip_address

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if model is not UNSET:
            field_dict["model"] = model
        if fw_type is not UNSET:
            field_dict["fw_type"] = fw_type
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        vendor = d.pop("vendor", UNSET)

        model = d.pop("model", UNSET)

        fw_type = d.pop("fw_type", UNSET)

        ip_address = d.pop("ip_address", UNSET)

        firewall_create = cls(
            name=name,
            vendor=vendor,
            model=model,
            fw_type=fw_type,
            ip_address=ip_address,
        )

        firewall_create.additional_properties = d
        return firewall_create

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
