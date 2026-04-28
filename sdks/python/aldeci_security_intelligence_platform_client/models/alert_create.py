from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AlertCreate")


@_attrs_define
class AlertCreate:
    """
    Attributes:
        org_id (str):
        alert_source (str | Unset):  Default: 'SIEM'.
        severity (str | Unset):  Default: 'medium'.
        category (str | Unset):  Default: 'other'.
        detected_at (None | str | Unset):
    """

    org_id: str
    alert_source: str | Unset = "SIEM"
    severity: str | Unset = "medium"
    category: str | Unset = "other"
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        alert_source = self.alert_source

        severity = self.severity

        category = self.category

        detected_at: None | str | Unset
        if isinstance(self.detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if alert_source is not UNSET:
            field_dict["alert_source"] = alert_source
        if severity is not UNSET:
            field_dict["severity"] = severity
        if category is not UNSET:
            field_dict["category"] = category
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        alert_source = d.pop("alert_source", UNSET)

        severity = d.pop("severity", UNSET)

        category = d.pop("category", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        alert_create = cls(
            org_id=org_id,
            alert_source=alert_source,
            severity=severity,
            category=category,
            detected_at=detected_at,
        )

        alert_create.additional_properties = d
        return alert_create

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
