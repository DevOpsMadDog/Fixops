from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.monitoring_response_latest_security_rating_type_0 import MonitoringResponseLatestSecurityRatingType0
    from ..models.monitoring_response_severity_breakdown import MonitoringResponseSeverityBreakdown
    from ..models.monitoring_response_signals_item import MonitoringResponseSignalsItem


T = TypeVar("T", bound="MonitoringResponse")


@_attrs_define
class MonitoringResponse:
    """Continuous monitoring data for a vendor.

    Attributes:
        vendor_id (str):
        total_signals (int):
        active_signals (int):
        severity_breakdown (MonitoringResponseSeverityBreakdown):
        latest_security_rating (MonitoringResponseLatestSecurityRatingType0 | None):
        signals (list[MonitoringResponseSignalsItem]):
    """

    vendor_id: str
    total_signals: int
    active_signals: int
    severity_breakdown: MonitoringResponseSeverityBreakdown
    latest_security_rating: MonitoringResponseLatestSecurityRatingType0 | None
    signals: list[MonitoringResponseSignalsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.monitoring_response_latest_security_rating_type_0 import (
            MonitoringResponseLatestSecurityRatingType0,
        )

        vendor_id = self.vendor_id

        total_signals = self.total_signals

        active_signals = self.active_signals

        severity_breakdown = self.severity_breakdown.to_dict()

        latest_security_rating: dict[str, Any] | None
        if isinstance(self.latest_security_rating, MonitoringResponseLatestSecurityRatingType0):
            latest_security_rating = self.latest_security_rating.to_dict()
        else:
            latest_security_rating = self.latest_security_rating

        signals = []
        for signals_item_data in self.signals:
            signals_item = signals_item_data.to_dict()
            signals.append(signals_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor_id": vendor_id,
                "total_signals": total_signals,
                "active_signals": active_signals,
                "severity_breakdown": severity_breakdown,
                "latest_security_rating": latest_security_rating,
                "signals": signals,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.monitoring_response_latest_security_rating_type_0 import (
            MonitoringResponseLatestSecurityRatingType0,
        )
        from ..models.monitoring_response_severity_breakdown import MonitoringResponseSeverityBreakdown
        from ..models.monitoring_response_signals_item import MonitoringResponseSignalsItem

        d = dict(src_dict)
        vendor_id = d.pop("vendor_id")

        total_signals = d.pop("total_signals")

        active_signals = d.pop("active_signals")

        severity_breakdown = MonitoringResponseSeverityBreakdown.from_dict(d.pop("severity_breakdown"))

        def _parse_latest_security_rating(data: object) -> MonitoringResponseLatestSecurityRatingType0 | None:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                latest_security_rating_type_0 = MonitoringResponseLatestSecurityRatingType0.from_dict(data)

                return latest_security_rating_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(MonitoringResponseLatestSecurityRatingType0 | None, data)

        latest_security_rating = _parse_latest_security_rating(d.pop("latest_security_rating"))

        signals = []
        _signals = d.pop("signals")
        for signals_item_data in _signals:
            signals_item = MonitoringResponseSignalsItem.from_dict(signals_item_data)

            signals.append(signals_item)

        monitoring_response = cls(
            vendor_id=vendor_id,
            total_signals=total_signals,
            active_signals=active_signals,
            severity_breakdown=severity_breakdown,
            latest_security_rating=latest_security_rating,
            signals=signals,
        )

        monitoring_response.additional_properties = d
        return monitoring_response

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
