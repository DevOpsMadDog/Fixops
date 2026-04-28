from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ShareIndicatorRequest")


@_attrs_define
class ShareIndicatorRequest:
    """
    Attributes:
        value (str):
        indicator_type (str | Unset):  Default: 'ip'.
        confidence (float | Unset):  Default: 0.8.
        severity (str | Unset):  Default: 'medium'.
        tlp_marking (str | Unset):  Default: 'AMBER'.
        source (str | Unset):  Default: 'aldeci'.
        expires_at (None | str | Unset):
    """

    value: str
    indicator_type: str | Unset = "ip"
    confidence: float | Unset = 0.8
    severity: str | Unset = "medium"
    tlp_marking: str | Unset = "AMBER"
    source: str | Unset = "aldeci"
    expires_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = self.value

        indicator_type = self.indicator_type

        confidence = self.confidence

        severity = self.severity

        tlp_marking = self.tlp_marking

        source = self.source

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "value": value,
            }
        )
        if indicator_type is not UNSET:
            field_dict["indicator_type"] = indicator_type
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if severity is not UNSET:
            field_dict["severity"] = severity
        if tlp_marking is not UNSET:
            field_dict["tlp_marking"] = tlp_marking
        if source is not UNSET:
            field_dict["source"] = source
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        value = d.pop("value")

        indicator_type = d.pop("indicator_type", UNSET)

        confidence = d.pop("confidence", UNSET)

        severity = d.pop("severity", UNSET)

        tlp_marking = d.pop("tlp_marking", UNSET)

        source = d.pop("source", UNSET)

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        share_indicator_request = cls(
            value=value,
            indicator_type=indicator_type,
            confidence=confidence,
            severity=severity,
            tlp_marking=tlp_marking,
            source=source,
            expires_at=expires_at,
        )

        share_indicator_request.additional_properties = d
        return share_indicator_request

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
