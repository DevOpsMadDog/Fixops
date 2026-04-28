from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.metrics_response_by_severity import MetricsResponseBySeverity
    from ..models.metrics_response_by_state import MetricsResponseByState
    from ..models.metrics_response_by_type import MetricsResponseByType


T = TypeVar("T", bound="MetricsResponse")


@_attrs_define
class MetricsResponse:
    """
    Attributes:
        total_created (int):
        total_open (int):
        total_closed (int):
        avg_time_to_close_hours (float):
        by_severity (MetricsResponseBySeverity):
        by_type (MetricsResponseByType):
        by_state (MetricsResponseByState):
    """

    total_created: int
    total_open: int
    total_closed: int
    avg_time_to_close_hours: float
    by_severity: MetricsResponseBySeverity
    by_type: MetricsResponseByType
    by_state: MetricsResponseByState
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total_created = self.total_created

        total_open = self.total_open

        total_closed = self.total_closed

        avg_time_to_close_hours = self.avg_time_to_close_hours

        by_severity = self.by_severity.to_dict()

        by_type = self.by_type.to_dict()

        by_state = self.by_state.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total_created": total_created,
                "total_open": total_open,
                "total_closed": total_closed,
                "avg_time_to_close_hours": avg_time_to_close_hours,
                "by_severity": by_severity,
                "by_type": by_type,
                "by_state": by_state,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.metrics_response_by_severity import MetricsResponseBySeverity
        from ..models.metrics_response_by_state import MetricsResponseByState
        from ..models.metrics_response_by_type import MetricsResponseByType

        d = dict(src_dict)
        total_created = d.pop("total_created")

        total_open = d.pop("total_open")

        total_closed = d.pop("total_closed")

        avg_time_to_close_hours = d.pop("avg_time_to_close_hours")

        by_severity = MetricsResponseBySeverity.from_dict(d.pop("by_severity"))

        by_type = MetricsResponseByType.from_dict(d.pop("by_type"))

        by_state = MetricsResponseByState.from_dict(d.pop("by_state"))

        metrics_response = cls(
            total_created=total_created,
            total_open=total_open,
            total_closed=total_closed,
            avg_time_to_close_hours=avg_time_to_close_hours,
            by_severity=by_severity,
            by_type=by_type,
            by_state=by_state,
        )

        metrics_response.additional_properties = d
        return metrics_response

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
