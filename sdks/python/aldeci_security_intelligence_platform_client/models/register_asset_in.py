from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterAssetIn")


@_attrs_define
class RegisterAssetIn:
    """
    Attributes:
        asset_name (str): Asset name
        asset_type (str | Unset): server|workstation|container|network_device|cloud_instance|database|application|iot
            Default: 'server'.
        criticality (str | Unset): critical|high|medium|low Default: 'medium'.
        ip_address (str | Unset): IP address Default: ''.
        os_type (str | Unset): Operating system type Default: ''.
        risk_score (float | Unset): Risk score Default: 0.0.
    """

    asset_name: str
    asset_type: str | Unset = "server"
    criticality: str | Unset = "medium"
    ip_address: str | Unset = ""
    os_type: str | Unset = ""
    risk_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_name = self.asset_name

        asset_type = self.asset_type

        criticality = self.criticality

        ip_address = self.ip_address

        os_type = self.os_type

        risk_score = self.risk_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_name": asset_name,
            }
        )
        if asset_type is not UNSET:
            field_dict["asset_type"] = asset_type
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if os_type is not UNSET:
            field_dict["os_type"] = os_type
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_name = d.pop("asset_name")

        asset_type = d.pop("asset_type", UNSET)

        criticality = d.pop("criticality", UNSET)

        ip_address = d.pop("ip_address", UNSET)

        os_type = d.pop("os_type", UNSET)

        risk_score = d.pop("risk_score", UNSET)

        register_asset_in = cls(
            asset_name=asset_name,
            asset_type=asset_type,
            criticality=criticality,
            ip_address=ip_address,
            os_type=os_type,
            risk_score=risk_score,
        )

        register_asset_in.additional_properties = d
        return register_asset_in

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
