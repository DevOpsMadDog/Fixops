from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="BaselineStats")


@_attrs_define
class BaselineStats:
    """Statistical baseline for a metric.

    Attributes:
        metric_name (str):
        org_id (str):
        mean (float):
        std_dev (float):
        min_value (float):
        max_value (float):
        sample_count (int):
        window_days (int):
        computed_at (datetime.datetime | Unset):
    """

    metric_name: str
    org_id: str
    mean: float
    std_dev: float
    min_value: float
    max_value: float
    sample_count: int
    window_days: int
    computed_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        metric_name = self.metric_name

        org_id = self.org_id

        mean = self.mean

        std_dev = self.std_dev

        min_value = self.min_value

        max_value = self.max_value

        sample_count = self.sample_count

        window_days = self.window_days

        computed_at: str | Unset = UNSET
        if not isinstance(self.computed_at, Unset):
            computed_at = self.computed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "metric_name": metric_name,
                "org_id": org_id,
                "mean": mean,
                "std_dev": std_dev,
                "min_value": min_value,
                "max_value": max_value,
                "sample_count": sample_count,
                "window_days": window_days,
            }
        )
        if computed_at is not UNSET:
            field_dict["computed_at"] = computed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        metric_name = d.pop("metric_name")

        org_id = d.pop("org_id")

        mean = d.pop("mean")

        std_dev = d.pop("std_dev")

        min_value = d.pop("min_value")

        max_value = d.pop("max_value")

        sample_count = d.pop("sample_count")

        window_days = d.pop("window_days")

        _computed_at = d.pop("computed_at", UNSET)
        computed_at: datetime.datetime | Unset
        if isinstance(_computed_at, Unset):
            computed_at = UNSET
        else:
            computed_at = isoparse(_computed_at)

        baseline_stats = cls(
            metric_name=metric_name,
            org_id=org_id,
            mean=mean,
            std_dev=std_dev,
            min_value=min_value,
            max_value=max_value,
            sample_count=sample_count,
            window_days=window_days,
            computed_at=computed_at,
        )

        baseline_stats.additional_properties = d
        return baseline_stats

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
