from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SpikeDropRequest")


@_attrs_define
class SpikeDropRequest:
    """Body for targeted spike / drop detection.

    Attributes:
        metric_name (str): Metric to analyse
        threshold_pct (float): Percentage deviation that triggers the anomaly
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    metric_name: str
    threshold_pct: float
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_name = self.metric_name

        threshold_pct = self.threshold_pct

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_name": metric_name,
                "threshold_pct": threshold_pct,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        metric_name = d.pop("metric_name")

        threshold_pct = d.pop("threshold_pct")

        org_id = d.pop("org_id", UNSET)

        spike_drop_request = cls(
            metric_name=metric_name,
            threshold_pct=threshold_pct,
            org_id=org_id,
        )

        spike_drop_request.additional_properties = d
        return spike_drop_request

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
