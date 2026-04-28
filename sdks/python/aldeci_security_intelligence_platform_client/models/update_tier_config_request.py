from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.plan_tier import PlanTier

T = TypeVar("T", bound="UpdateTierConfigRequest")


@_attrs_define
class UpdateTierConfigRequest:
    """
    Attributes:
        tier (PlanTier):
        requests_per_minute (int):
        requests_per_hour (int):
        burst_limit (int):
        sustained_limit (int):
    """

    tier: PlanTier
    requests_per_minute: int
    requests_per_hour: int
    burst_limit: int
    sustained_limit: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tier = self.tier.value

        requests_per_minute = self.requests_per_minute

        requests_per_hour = self.requests_per_hour

        burst_limit = self.burst_limit

        sustained_limit = self.sustained_limit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tier": tier,
                "requests_per_minute": requests_per_minute,
                "requests_per_hour": requests_per_hour,
                "burst_limit": burst_limit,
                "sustained_limit": sustained_limit,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tier = PlanTier(d.pop("tier"))

        requests_per_minute = d.pop("requests_per_minute")

        requests_per_hour = d.pop("requests_per_hour")

        burst_limit = d.pop("burst_limit")

        sustained_limit = d.pop("sustained_limit")

        update_tier_config_request = cls(
            tier=tier,
            requests_per_minute=requests_per_minute,
            requests_per_hour=requests_per_hour,
            burst_limit=burst_limit,
            sustained_limit=sustained_limit,
        )

        update_tier_config_request.additional_properties = d
        return update_tier_config_request

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
