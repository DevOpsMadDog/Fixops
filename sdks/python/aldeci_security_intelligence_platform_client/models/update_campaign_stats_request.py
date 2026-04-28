from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateCampaignStatsRequest")


@_attrs_define
class UpdateCampaignStatsRequest:
    """
    Attributes:
        asset_count (int | None | Unset):
        interaction_count (int | None | Unset):
        unique_attacker_ips (int | None | Unset):
    """

    asset_count: int | None | Unset = UNSET
    interaction_count: int | None | Unset = UNSET
    unique_attacker_ips: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_count: int | None | Unset
        if isinstance(self.asset_count, Unset):
            asset_count = UNSET
        else:
            asset_count = self.asset_count

        interaction_count: int | None | Unset
        if isinstance(self.interaction_count, Unset):
            interaction_count = UNSET
        else:
            interaction_count = self.interaction_count

        unique_attacker_ips: int | None | Unset
        if isinstance(self.unique_attacker_ips, Unset):
            unique_attacker_ips = UNSET
        else:
            unique_attacker_ips = self.unique_attacker_ips

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if asset_count is not UNSET:
            field_dict["asset_count"] = asset_count
        if interaction_count is not UNSET:
            field_dict["interaction_count"] = interaction_count
        if unique_attacker_ips is not UNSET:
            field_dict["unique_attacker_ips"] = unique_attacker_ips

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_asset_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        asset_count = _parse_asset_count(d.pop("asset_count", UNSET))

        def _parse_interaction_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        interaction_count = _parse_interaction_count(d.pop("interaction_count", UNSET))

        def _parse_unique_attacker_ips(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        unique_attacker_ips = _parse_unique_attacker_ips(d.pop("unique_attacker_ips", UNSET))

        update_campaign_stats_request = cls(
            asset_count=asset_count,
            interaction_count=interaction_count,
            unique_attacker_ips=unique_attacker_ips,
        )

        update_campaign_stats_request.additional_properties = d
        return update_campaign_stats_request

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
