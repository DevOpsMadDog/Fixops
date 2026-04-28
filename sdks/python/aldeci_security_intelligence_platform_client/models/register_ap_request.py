from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterAPRequest")


@_attrs_define
class RegisterAPRequest:
    """
    Attributes:
        name (str): Access point name
        band (str): Frequency band: 2.4ghz, 5ghz, 6ghz, dual_band
        org_id (str | Unset):  Default: 'default'.
        security_protocol (str | Unset): Security protocol: open, wep, wpa, wpa2, wpa3 Default: 'wpa2'.
        ssid (None | str | Unset):
        bssid (None | str | Unset):
        location (None | str | Unset):
    """

    name: str
    band: str
    org_id: str | Unset = "default"
    security_protocol: str | Unset = "wpa2"
    ssid: None | str | Unset = UNSET
    bssid: None | str | Unset = UNSET
    location: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        band = self.band

        org_id = self.org_id

        security_protocol = self.security_protocol

        ssid: None | str | Unset
        if isinstance(self.ssid, Unset):
            ssid = UNSET
        else:
            ssid = self.ssid

        bssid: None | str | Unset
        if isinstance(self.bssid, Unset):
            bssid = UNSET
        else:
            bssid = self.bssid

        location: None | str | Unset
        if isinstance(self.location, Unset):
            location = UNSET
        else:
            location = self.location

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "band": band,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if security_protocol is not UNSET:
            field_dict["security_protocol"] = security_protocol
        if ssid is not UNSET:
            field_dict["ssid"] = ssid
        if bssid is not UNSET:
            field_dict["bssid"] = bssid
        if location is not UNSET:
            field_dict["location"] = location

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        band = d.pop("band")

        org_id = d.pop("org_id", UNSET)

        security_protocol = d.pop("security_protocol", UNSET)

        def _parse_ssid(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ssid = _parse_ssid(d.pop("ssid", UNSET))

        def _parse_bssid(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        bssid = _parse_bssid(d.pop("bssid", UNSET))

        def _parse_location(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        location = _parse_location(d.pop("location", UNSET))

        register_ap_request = cls(
            name=name,
            band=band,
            org_id=org_id,
            security_protocol=security_protocol,
            ssid=ssid,
            bssid=bssid,
            location=location,
        )

        register_ap_request.additional_properties = d
        return register_ap_request

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
