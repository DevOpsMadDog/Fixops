from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IngestLoginEventRequest")


@_attrs_define
class IngestLoginEventRequest:
    """
    Attributes:
        event_type (str | Unset):  Default: 'login'.
        src_ip (str | Unset):  Default: ''.
        geo_country (str | Unset):  Default: ''.
        device_id (str | Unset):  Default: ''.
        success (bool | Unset):  Default: True.
        risk_indicators (list[str] | Unset):
        observed_at (None | str | Unset):
    """

    event_type: str | Unset = "login"
    src_ip: str | Unset = ""
    geo_country: str | Unset = ""
    device_id: str | Unset = ""
    success: bool | Unset = True
    risk_indicators: list[str] | Unset = UNSET
    observed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_type = self.event_type

        src_ip = self.src_ip

        geo_country = self.geo_country

        device_id = self.device_id

        success = self.success

        risk_indicators: list[str] | Unset = UNSET
        if not isinstance(self.risk_indicators, Unset):
            risk_indicators = self.risk_indicators

        observed_at: None | str | Unset
        if isinstance(self.observed_at, Unset):
            observed_at = UNSET
        else:
            observed_at = self.observed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if event_type is not UNSET:
            field_dict["event_type"] = event_type
        if src_ip is not UNSET:
            field_dict["src_ip"] = src_ip
        if geo_country is not UNSET:
            field_dict["geo_country"] = geo_country
        if device_id is not UNSET:
            field_dict["device_id"] = device_id
        if success is not UNSET:
            field_dict["success"] = success
        if risk_indicators is not UNSET:
            field_dict["risk_indicators"] = risk_indicators
        if observed_at is not UNSET:
            field_dict["observed_at"] = observed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        event_type = d.pop("event_type", UNSET)

        src_ip = d.pop("src_ip", UNSET)

        geo_country = d.pop("geo_country", UNSET)

        device_id = d.pop("device_id", UNSET)

        success = d.pop("success", UNSET)

        risk_indicators = cast(list[str], d.pop("risk_indicators", UNSET))

        def _parse_observed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        observed_at = _parse_observed_at(d.pop("observed_at", UNSET))

        ingest_login_event_request = cls(
            event_type=event_type,
            src_ip=src_ip,
            geo_country=geo_country,
            device_id=device_id,
            success=success,
            risk_indicators=risk_indicators,
            observed_at=observed_at,
        )

        ingest_login_event_request.additional_properties = d
        return ingest_login_event_request

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
