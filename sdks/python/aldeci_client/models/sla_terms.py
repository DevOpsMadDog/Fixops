from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SLATerms")


@_attrs_define
class SLATerms:
    """Service Level Agreement terms.

    Attributes:
        uptime_percent (float | Unset): Uptime SLA % Default: 99.9.
        incident_response_hours (int | Unset): Hours to acknowledge incident Default: 4.
        breach_notification_hours (int | Unset): Hours to notify of breach Default: 72.
        data_return_days (int | Unset): Days to return data on termination Default: 30.
        review_frequency_months (int | Unset): SLA review frequency in months Default: 12.
    """

    uptime_percent: float | Unset = 99.9
    incident_response_hours: int | Unset = 4
    breach_notification_hours: int | Unset = 72
    data_return_days: int | Unset = 30
    review_frequency_months: int | Unset = 12
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        uptime_percent = self.uptime_percent

        incident_response_hours = self.incident_response_hours

        breach_notification_hours = self.breach_notification_hours

        data_return_days = self.data_return_days

        review_frequency_months = self.review_frequency_months

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if uptime_percent is not UNSET:
            field_dict["uptime_percent"] = uptime_percent
        if incident_response_hours is not UNSET:
            field_dict["incident_response_hours"] = incident_response_hours
        if breach_notification_hours is not UNSET:
            field_dict["breach_notification_hours"] = breach_notification_hours
        if data_return_days is not UNSET:
            field_dict["data_return_days"] = data_return_days
        if review_frequency_months is not UNSET:
            field_dict["review_frequency_months"] = review_frequency_months

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        uptime_percent = d.pop("uptime_percent", UNSET)

        incident_response_hours = d.pop("incident_response_hours", UNSET)

        breach_notification_hours = d.pop("breach_notification_hours", UNSET)

        data_return_days = d.pop("data_return_days", UNSET)

        review_frequency_months = d.pop("review_frequency_months", UNSET)

        sla_terms = cls(
            uptime_percent=uptime_percent,
            incident_response_hours=incident_response_hours,
            breach_notification_hours=breach_notification_hours,
            data_return_days=data_return_days,
            review_frequency_months=review_frequency_months,
        )

        sla_terms.additional_properties = d
        return sla_terms

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
