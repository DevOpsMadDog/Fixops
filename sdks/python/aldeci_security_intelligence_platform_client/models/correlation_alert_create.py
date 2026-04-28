from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CorrelationAlertCreate")


@_attrs_define
class CorrelationAlertCreate:
    """
    Attributes:
        title (str):
        rule_name (str):
        org_id (str | Unset):  Default: 'default'.
        severity (str | Unset):  Default: 'medium'.
        matched_events (list[str] | Unset):
    """

    title: str
    rule_name: str
    org_id: str | Unset = "default"
    severity: str | Unset = "medium"
    matched_events: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        rule_name = self.rule_name

        org_id = self.org_id

        severity = self.severity

        matched_events: list[str] | Unset = UNSET
        if not isinstance(self.matched_events, Unset):
            matched_events = self.matched_events

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "rule_name": rule_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if severity is not UNSET:
            field_dict["severity"] = severity
        if matched_events is not UNSET:
            field_dict["matched_events"] = matched_events

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        rule_name = d.pop("rule_name")

        org_id = d.pop("org_id", UNSET)

        severity = d.pop("severity", UNSET)

        matched_events = cast(list[str], d.pop("matched_events", UNSET))

        correlation_alert_create = cls(
            title=title,
            rule_name=rule_name,
            org_id=org_id,
            severity=severity,
            matched_events=matched_events,
        )

        correlation_alert_create.additional_properties = d
        return correlation_alert_create

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
