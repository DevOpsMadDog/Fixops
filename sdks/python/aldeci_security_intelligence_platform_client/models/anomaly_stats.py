from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.anomaly_stats_by_severity import AnomalyStatsBySeverity
    from ..models.anomaly_stats_by_type import AnomalyStatsByType


T = TypeVar("T", bound="AnomalyStats")


@_attrs_define
class AnomalyStats:
    """Summary of anomalies for an org.

    Attributes:
        org_id (str):
        total (int):
        by_type (AnomalyStatsByType):
        by_severity (AnomalyStatsBySeverity):
        unacknowledged (int):
        oldest_unacked (datetime.datetime | None):
        newest (datetime.datetime | None):
    """

    org_id: str
    total: int
    by_type: AnomalyStatsByType
    by_severity: AnomalyStatsBySeverity
    unacknowledged: int
    oldest_unacked: datetime.datetime | None
    newest: datetime.datetime | None
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total = self.total

        by_type = self.by_type.to_dict()

        by_severity = self.by_severity.to_dict()

        unacknowledged = self.unacknowledged

        oldest_unacked: None | str
        if isinstance(self.oldest_unacked, datetime.datetime):
            oldest_unacked = self.oldest_unacked.isoformat()
        else:
            oldest_unacked = self.oldest_unacked

        newest: None | str
        if isinstance(self.newest, datetime.datetime):
            newest = self.newest.isoformat()
        else:
            newest = self.newest

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total": total,
                "by_type": by_type,
                "by_severity": by_severity,
                "unacknowledged": unacknowledged,
                "oldest_unacked": oldest_unacked,
                "newest": newest,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.anomaly_stats_by_severity import AnomalyStatsBySeverity
        from ..models.anomaly_stats_by_type import AnomalyStatsByType

        d = dict(src_dict)
        org_id = d.pop("org_id")

        total = d.pop("total")

        by_type = AnomalyStatsByType.from_dict(d.pop("by_type"))

        by_severity = AnomalyStatsBySeverity.from_dict(d.pop("by_severity"))

        unacknowledged = d.pop("unacknowledged")

        def _parse_oldest_unacked(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                oldest_unacked_type_0 = isoparse(data)

                return oldest_unacked_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        oldest_unacked = _parse_oldest_unacked(d.pop("oldest_unacked"))

        def _parse_newest(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                newest_type_0 = isoparse(data)

                return newest_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        newest = _parse_newest(d.pop("newest"))

        anomaly_stats = cls(
            org_id=org_id,
            total=total,
            by_type=by_type,
            by_severity=by_severity,
            unacknowledged=unacknowledged,
            oldest_unacked=oldest_unacked,
            newest=newest,
        )

        anomaly_stats.additional_properties = d
        return anomaly_stats

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
