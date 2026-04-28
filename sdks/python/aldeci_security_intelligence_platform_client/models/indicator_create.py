from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IndicatorCreate")


@_attrs_define
class IndicatorCreate:
    """
    Attributes:
        indicator_value (str):
        indicator_type (str):
        source (str | Unset):  Default: ''.
        confidence (float | Unset):  Default: 0.5.
        severity (str | Unset):  Default: 'medium'.
        tlp (str | Unset):  Default: 'amber'.
        tags (list[str] | Unset):
        expiry_at (None | str | Unset):
    """

    indicator_value: str
    indicator_type: str
    source: str | Unset = ""
    confidence: float | Unset = 0.5
    severity: str | Unset = "medium"
    tlp: str | Unset = "amber"
    tags: list[str] | Unset = UNSET
    expiry_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        indicator_value = self.indicator_value

        indicator_type = self.indicator_type

        source = self.source

        confidence = self.confidence

        severity = self.severity

        tlp = self.tlp

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        expiry_at: None | str | Unset
        if isinstance(self.expiry_at, Unset):
            expiry_at = UNSET
        else:
            expiry_at = self.expiry_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "indicator_value": indicator_value,
                "indicator_type": indicator_type,
            }
        )
        if source is not UNSET:
            field_dict["source"] = source
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if severity is not UNSET:
            field_dict["severity"] = severity
        if tlp is not UNSET:
            field_dict["tlp"] = tlp
        if tags is not UNSET:
            field_dict["tags"] = tags
        if expiry_at is not UNSET:
            field_dict["expiry_at"] = expiry_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        indicator_value = d.pop("indicator_value")

        indicator_type = d.pop("indicator_type")

        source = d.pop("source", UNSET)

        confidence = d.pop("confidence", UNSET)

        severity = d.pop("severity", UNSET)

        tlp = d.pop("tlp", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        def _parse_expiry_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expiry_at = _parse_expiry_at(d.pop("expiry_at", UNSET))

        indicator_create = cls(
            indicator_value=indicator_value,
            indicator_type=indicator_type,
            source=source,
            confidence=confidence,
            severity=severity,
            tlp=tlp,
            tags=tags,
            expiry_at=expiry_at,
        )

        indicator_create.additional_properties = d
        return indicator_create

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
