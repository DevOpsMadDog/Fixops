from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatCreate")


@_attrs_define
class ThreatCreate:
    """
    Attributes:
        threat_type (str):
        user_id (str):
        source_ip (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        confidence (float | Unset):  Default: 50.0.
        indicators (list[str] | Unset):
    """

    threat_type: str
    user_id: str
    source_ip: str | Unset = ""
    severity: str | Unset = "medium"
    confidence: float | Unset = 50.0
    indicators: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        threat_type = self.threat_type

        user_id = self.user_id

        source_ip = self.source_ip

        severity = self.severity

        confidence = self.confidence

        indicators: list[str] | Unset = UNSET
        if not isinstance(self.indicators, Unset):
            indicators = self.indicators

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "threat_type": threat_type,
                "user_id": user_id,
            }
        )
        if source_ip is not UNSET:
            field_dict["source_ip"] = source_ip
        if severity is not UNSET:
            field_dict["severity"] = severity
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if indicators is not UNSET:
            field_dict["indicators"] = indicators

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        threat_type = d.pop("threat_type")

        user_id = d.pop("user_id")

        source_ip = d.pop("source_ip", UNSET)

        severity = d.pop("severity", UNSET)

        confidence = d.pop("confidence", UNSET)

        indicators = cast(list[str], d.pop("indicators", UNSET))

        threat_create = cls(
            threat_type=threat_type,
            user_id=user_id,
            source_ip=source_ip,
            severity=severity,
            confidence=confidence,
            indicators=indicators,
        )

        threat_create.additional_properties = d
        return threat_create

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
