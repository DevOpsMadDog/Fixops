from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="PrioritizationSummary")


@_attrs_define
class PrioritizationSummary:
    """Result of a re-prioritization run.

    Attributes:
        org_id (str):
        vulns_evaluated (int):
        epss_refreshed (int):
        duration_ms (float):
        critical_count (int):
        high_count (int):
        medium_count (int):
        low_count (int):
        info_count (int):
        triggered_at (datetime.datetime | Unset):
    """

    org_id: str
    vulns_evaluated: int
    epss_refreshed: int
    duration_ms: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    triggered_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        vulns_evaluated = self.vulns_evaluated

        epss_refreshed = self.epss_refreshed

        duration_ms = self.duration_ms

        critical_count = self.critical_count

        high_count = self.high_count

        medium_count = self.medium_count

        low_count = self.low_count

        info_count = self.info_count

        triggered_at: str | Unset = UNSET
        if not isinstance(self.triggered_at, Unset):
            triggered_at = self.triggered_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "vulns_evaluated": vulns_evaluated,
                "epss_refreshed": epss_refreshed,
                "duration_ms": duration_ms,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "info_count": info_count,
            }
        )
        if triggered_at is not UNSET:
            field_dict["triggered_at"] = triggered_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        vulns_evaluated = d.pop("vulns_evaluated")

        epss_refreshed = d.pop("epss_refreshed")

        duration_ms = d.pop("duration_ms")

        critical_count = d.pop("critical_count")

        high_count = d.pop("high_count")

        medium_count = d.pop("medium_count")

        low_count = d.pop("low_count")

        info_count = d.pop("info_count")

        _triggered_at = d.pop("triggered_at", UNSET)
        triggered_at: datetime.datetime | Unset
        if isinstance(_triggered_at, Unset):
            triggered_at = UNSET
        else:
            triggered_at = isoparse(_triggered_at)

        prioritization_summary = cls(
            org_id=org_id,
            vulns_evaluated=vulns_evaluated,
            epss_refreshed=epss_refreshed,
            duration_ms=duration_ms,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            triggered_at=triggered_at,
        )

        prioritization_summary.additional_properties = d
        return prioritization_summary

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
