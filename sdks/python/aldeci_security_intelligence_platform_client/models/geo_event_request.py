from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GeoEventRequest")


@_attrs_define
class GeoEventRequest:
    """
    Attributes:
        ip (str): Source IP address
        country_code (str): ISO 3166-1 alpha-2 country code
        country_name (str): Human-readable country name
        org_id (str | Unset): Organisation identifier Default: 'default'.
        city (str | Unset): City name Default: ''.
        lat (float | Unset): Latitude Default: 0.0.
        lon (float | Unset): Longitude Default: 0.0.
        event_type (str | Unset): One of: login, scan, attack, access Default: 'access'.
        risk_level (str | Unset): One of: low, medium, high, critical Default: 'low'.
        user_id (str | Unset): Associated user ID Default: ''.
    """

    ip: str
    country_code: str
    country_name: str
    org_id: str | Unset = "default"
    city: str | Unset = ""
    lat: float | Unset = 0.0
    lon: float | Unset = 0.0
    event_type: str | Unset = "access"
    risk_level: str | Unset = "low"
    user_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ip = self.ip

        country_code = self.country_code

        country_name = self.country_name

        org_id = self.org_id

        city = self.city

        lat = self.lat

        lon = self.lon

        event_type = self.event_type

        risk_level = self.risk_level

        user_id = self.user_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ip": ip,
                "country_code": country_code,
                "country_name": country_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if city is not UNSET:
            field_dict["city"] = city
        if lat is not UNSET:
            field_dict["lat"] = lat
        if lon is not UNSET:
            field_dict["lon"] = lon
        if event_type is not UNSET:
            field_dict["event_type"] = event_type
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if user_id is not UNSET:
            field_dict["user_id"] = user_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ip = d.pop("ip")

        country_code = d.pop("country_code")

        country_name = d.pop("country_name")

        org_id = d.pop("org_id", UNSET)

        city = d.pop("city", UNSET)

        lat = d.pop("lat", UNSET)

        lon = d.pop("lon", UNSET)

        event_type = d.pop("event_type", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        user_id = d.pop("user_id", UNSET)

        geo_event_request = cls(
            ip=ip,
            country_code=country_code,
            country_name=country_name,
            org_id=org_id,
            city=city,
            lat=lat,
            lon=lon,
            event_type=event_type,
            risk_level=risk_level,
            user_id=user_id,
        )

        geo_event_request.additional_properties = d
        return geo_event_request

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
