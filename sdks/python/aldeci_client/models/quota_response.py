from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.quota_response_current_usage import QuotaResponseCurrentUsage


T = TypeVar("T", bound="QuotaResponse")


@_attrs_define
class QuotaResponse:
    """
    Attributes:
        org_id (str):
        tier (str):
        requests_per_minute (int):
        requests_per_hour (int):
        requests_per_day (int):
        burst_limit (int):
        current_usage (QuotaResponseCurrentUsage):
    """

    org_id: str
    tier: str
    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_limit: int
    current_usage: QuotaResponseCurrentUsage
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        tier = self.tier

        requests_per_minute = self.requests_per_minute

        requests_per_hour = self.requests_per_hour

        requests_per_day = self.requests_per_day

        burst_limit = self.burst_limit

        current_usage = self.current_usage.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "tier": tier,
                "requests_per_minute": requests_per_minute,
                "requests_per_hour": requests_per_hour,
                "requests_per_day": requests_per_day,
                "burst_limit": burst_limit,
                "current_usage": current_usage,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.quota_response_current_usage import QuotaResponseCurrentUsage

        d = dict(src_dict)
        org_id = d.pop("org_id")

        tier = d.pop("tier")

        requests_per_minute = d.pop("requests_per_minute")

        requests_per_hour = d.pop("requests_per_hour")

        requests_per_day = d.pop("requests_per_day")

        burst_limit = d.pop("burst_limit")

        current_usage = QuotaResponseCurrentUsage.from_dict(d.pop("current_usage"))

        quota_response = cls(
            org_id=org_id,
            tier=tier,
            requests_per_minute=requests_per_minute,
            requests_per_hour=requests_per_hour,
            requests_per_day=requests_per_day,
            burst_limit=burst_limit,
            current_usage=current_usage,
        )

        quota_response.additional_properties = d
        return quota_response

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
