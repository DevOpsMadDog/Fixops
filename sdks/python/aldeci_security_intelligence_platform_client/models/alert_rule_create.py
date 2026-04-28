from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AlertRuleCreate")


@_attrs_define
class AlertRuleCreate:
    """
    Attributes:
        name (str): Alert rule name
        telemetry_type (str): Telemetry type to monitor
        aggregation (str | Unset): avg/sum/max/min/count/p95/p99 Default: 'avg'.
        threshold (float | Unset): Threshold value Default: 0.0.
        operator (str | Unset): gt/lt/gte/lte Default: 'gt'.
        source (str | Unset): Optional source filter Default: ''.
    """

    name: str
    telemetry_type: str
    aggregation: str | Unset = "avg"
    threshold: float | Unset = 0.0
    operator: str | Unset = "gt"
    source: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        telemetry_type = self.telemetry_type

        aggregation = self.aggregation

        threshold = self.threshold

        operator = self.operator

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "telemetry_type": telemetry_type,
            }
        )
        if aggregation is not UNSET:
            field_dict["aggregation"] = aggregation
        if threshold is not UNSET:
            field_dict["threshold"] = threshold
        if operator is not UNSET:
            field_dict["operator"] = operator
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        telemetry_type = d.pop("telemetry_type")

        aggregation = d.pop("aggregation", UNSET)

        threshold = d.pop("threshold", UNSET)

        operator = d.pop("operator", UNSET)

        source = d.pop("source", UNSET)

        alert_rule_create = cls(
            name=name,
            telemetry_type=telemetry_type,
            aggregation=aggregation,
            threshold=threshold,
            operator=operator,
            source=source,
        )

        alert_rule_create.additional_properties = d
        return alert_rule_create

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
