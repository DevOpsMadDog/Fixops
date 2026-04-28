from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SubmitAlertRequest")


@_attrs_define
class SubmitAlertRequest:
    """
    Attributes:
        alert_id (str): Unique alert identifier from source system
        alert_source (str): Source system name (e.g. SIEM, EDR)
        raw_indicator (str): Raw indicator value to enrich
        severity (str | Unset): critical | high | medium | low Default: 'medium'.
        indicator_type (str | Unset): ip | domain | url | hash | email | user | process | registry Default: 'ip'.
    """

    alert_id: str
    alert_source: str
    raw_indicator: str
    severity: str | Unset = "medium"
    indicator_type: str | Unset = "ip"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        alert_id = self.alert_id

        alert_source = self.alert_source

        raw_indicator = self.raw_indicator

        severity = self.severity

        indicator_type = self.indicator_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "alert_id": alert_id,
                "alert_source": alert_source,
                "raw_indicator": raw_indicator,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if indicator_type is not UNSET:
            field_dict["indicator_type"] = indicator_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        alert_id = d.pop("alert_id")

        alert_source = d.pop("alert_source")

        raw_indicator = d.pop("raw_indicator")

        severity = d.pop("severity", UNSET)

        indicator_type = d.pop("indicator_type", UNSET)

        submit_alert_request = cls(
            alert_id=alert_id,
            alert_source=alert_source,
            raw_indicator=raw_indicator,
            severity=severity,
            indicator_type=indicator_type,
        )

        submit_alert_request.additional_properties = d
        return submit_alert_request

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
