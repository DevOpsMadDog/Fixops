from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.kpi_category import KPICategory
from ..models.kpi_trend import KPITrend
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.kpi_metadata import KPIMetadata


T = TypeVar("T", bound="KPI")


@_attrs_define
class KPI:
    """A security KPI data point.

    Attributes:
        name (str): Machine-readable KPI name (e.g. mttd_minutes)
        value (float): Current KPI value
        category (KPICategory): Category grouping for security KPIs.
        id (str | Unset):
        target (float | None | Unset): Target value for this KPI
        unit (str | Unset): Unit of measure (minutes, %, count, etc.) Default: ''.
        trend (KPITrend | Unset): Directional trend for a KPI value.
        period (str | Unset): Reporting period (e.g. 2026-04, daily, weekly) Default: ''.
        org_id (str | Unset): Organisation identifier Default: 'default'.
        recorded_at (datetime.datetime | Unset):
        metadata (KPIMetadata | Unset):
    """

    name: str
    value: float
    category: KPICategory
    id: str | Unset = UNSET
    target: float | None | Unset = UNSET
    unit: str | Unset = ""
    trend: KPITrend | Unset = UNSET
    period: str | Unset = ""
    org_id: str | Unset = "default"
    recorded_at: datetime.datetime | Unset = UNSET
    metadata: KPIMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        value = self.value

        category = self.category.value

        id = self.id

        target: float | None | Unset
        if isinstance(self.target, Unset):
            target = UNSET
        else:
            target = self.target

        unit = self.unit

        trend: str | Unset = UNSET
        if not isinstance(self.trend, Unset):
            trend = self.trend.value

        period = self.period

        org_id = self.org_id

        recorded_at: str | Unset = UNSET
        if not isinstance(self.recorded_at, Unset):
            recorded_at = self.recorded_at.isoformat()

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "value": value,
                "category": category,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if target is not UNSET:
            field_dict["target"] = target
        if unit is not UNSET:
            field_dict["unit"] = unit
        if trend is not UNSET:
            field_dict["trend"] = trend
        if period is not UNSET:
            field_dict["period"] = period
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if recorded_at is not UNSET:
            field_dict["recorded_at"] = recorded_at
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.kpi_metadata import KPIMetadata

        d = dict(src_dict)
        name = d.pop("name")

        value = d.pop("value")

        category = KPICategory(d.pop("category"))

        id = d.pop("id", UNSET)

        def _parse_target(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        target = _parse_target(d.pop("target", UNSET))

        unit = d.pop("unit", UNSET)

        _trend = d.pop("trend", UNSET)
        trend: KPITrend | Unset
        if isinstance(_trend, Unset):
            trend = UNSET
        else:
            trend = KPITrend(_trend)

        period = d.pop("period", UNSET)

        org_id = d.pop("org_id", UNSET)

        _recorded_at = d.pop("recorded_at", UNSET)
        recorded_at: datetime.datetime | Unset
        if isinstance(_recorded_at, Unset):
            recorded_at = UNSET
        else:
            recorded_at = isoparse(_recorded_at)

        _metadata = d.pop("metadata", UNSET)
        metadata: KPIMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = KPIMetadata.from_dict(_metadata)

        kpi = cls(
            name=name,
            value=value,
            category=category,
            id=id,
            target=target,
            unit=unit,
            trend=trend,
            period=period,
            org_id=org_id,
            recorded_at=recorded_at,
            metadata=metadata,
        )

        kpi.additional_properties = d
        return kpi

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
