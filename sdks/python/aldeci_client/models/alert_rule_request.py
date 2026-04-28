from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AlertRuleRequest")


@_attrs_define
class AlertRuleRequest:
    """
    Attributes:
        interface_id (str): Target interface ID
        org_id (str | Unset): Organisation ID Default: 'default'.
        metric (str | Unset): Metric to monitor Default: 'bytes_in'.
        threshold (float | Unset): Alert threshold value Default: 0.0.
        severity (str | Unset): Severity: critical/high/medium/low Default: 'medium'.
    """

    interface_id: str
    org_id: str | Unset = "default"
    metric: str | Unset = "bytes_in"
    threshold: float | Unset = 0.0
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        interface_id = self.interface_id

        org_id = self.org_id

        metric = self.metric

        threshold = self.threshold

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "interface_id": interface_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if metric is not UNSET:
            field_dict["metric"] = metric
        if threshold is not UNSET:
            field_dict["threshold"] = threshold
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        interface_id = d.pop("interface_id")

        org_id = d.pop("org_id", UNSET)

        metric = d.pop("metric", UNSET)

        threshold = d.pop("threshold", UNSET)

        severity = d.pop("severity", UNSET)

        alert_rule_request = cls(
            interface_id=interface_id,
            org_id=org_id,
            metric=metric,
            threshold=threshold,
            severity=severity,
        )

        alert_rule_request.additional_properties = d
        return alert_rule_request

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
