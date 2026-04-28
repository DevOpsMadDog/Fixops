from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="ConnectorMetricsEntry")


@_attrs_define
class ConnectorMetricsEntry:
    """Metrics for a single connector.

    Attributes:
        name (str): Connector name
        pull_count_24h (int): Successful pulls in last 24h
        pull_count_7d (int): Successful pulls in last 7d
        error_count_24h (int): Errors in last 24h
        error_count_7d (int): Errors in last 7d
        error_rate_24h (float): Error rate % (0.0-1.0)
        findings_ingested_24h (int): Findings ingested in last 24h
        findings_ingested_7d (int): Findings ingested in last 7d
        last_pull_time (datetime.datetime | None | Unset): Last successful pull
        avg_pull_duration_seconds (float | None | Unset): Average pull duration
    """

    name: str
    pull_count_24h: int
    pull_count_7d: int
    error_count_24h: int
    error_count_7d: int
    error_rate_24h: float
    findings_ingested_24h: int
    findings_ingested_7d: int
    last_pull_time: datetime.datetime | None | Unset = UNSET
    avg_pull_duration_seconds: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        pull_count_24h = self.pull_count_24h

        pull_count_7d = self.pull_count_7d

        error_count_24h = self.error_count_24h

        error_count_7d = self.error_count_7d

        error_rate_24h = self.error_rate_24h

        findings_ingested_24h = self.findings_ingested_24h

        findings_ingested_7d = self.findings_ingested_7d

        last_pull_time: None | str | Unset
        if isinstance(self.last_pull_time, Unset):
            last_pull_time = UNSET
        elif isinstance(self.last_pull_time, datetime.datetime):
            last_pull_time = self.last_pull_time.isoformat()
        else:
            last_pull_time = self.last_pull_time

        avg_pull_duration_seconds: float | None | Unset
        if isinstance(self.avg_pull_duration_seconds, Unset):
            avg_pull_duration_seconds = UNSET
        else:
            avg_pull_duration_seconds = self.avg_pull_duration_seconds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "pull_count_24h": pull_count_24h,
                "pull_count_7d": pull_count_7d,
                "error_count_24h": error_count_24h,
                "error_count_7d": error_count_7d,
                "error_rate_24h": error_rate_24h,
                "findings_ingested_24h": findings_ingested_24h,
                "findings_ingested_7d": findings_ingested_7d,
            }
        )
        if last_pull_time is not UNSET:
            field_dict["last_pull_time"] = last_pull_time
        if avg_pull_duration_seconds is not UNSET:
            field_dict["avg_pull_duration_seconds"] = avg_pull_duration_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        pull_count_24h = d.pop("pull_count_24h")

        pull_count_7d = d.pop("pull_count_7d")

        error_count_24h = d.pop("error_count_24h")

        error_count_7d = d.pop("error_count_7d")

        error_rate_24h = d.pop("error_rate_24h")

        findings_ingested_24h = d.pop("findings_ingested_24h")

        findings_ingested_7d = d.pop("findings_ingested_7d")

        def _parse_last_pull_time(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                last_pull_time_type_0 = isoparse(data)

                return last_pull_time_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        last_pull_time = _parse_last_pull_time(d.pop("last_pull_time", UNSET))

        def _parse_avg_pull_duration_seconds(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        avg_pull_duration_seconds = _parse_avg_pull_duration_seconds(d.pop("avg_pull_duration_seconds", UNSET))

        connector_metrics_entry = cls(
            name=name,
            pull_count_24h=pull_count_24h,
            pull_count_7d=pull_count_7d,
            error_count_24h=error_count_24h,
            error_count_7d=error_count_7d,
            error_rate_24h=error_rate_24h,
            findings_ingested_24h=findings_ingested_24h,
            findings_ingested_7d=findings_ingested_7d,
            last_pull_time=last_pull_time,
            avg_pull_duration_seconds=avg_pull_duration_seconds,
        )

        connector_metrics_entry.additional_properties = d
        return connector_metrics_entry

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
