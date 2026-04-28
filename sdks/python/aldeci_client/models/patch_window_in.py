from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PatchWindowIn")


@_attrs_define
class PatchWindowIn:
    """
    Attributes:
        name (str):
        schedule_cron (str | Unset):  Default: ''.
        asset_groups (list[str] | Unset):
        auto_approve (bool | Unset):  Default: False.
        max_batch_pct (int | Unset):  Default: 20.
    """

    name: str
    schedule_cron: str | Unset = ""
    asset_groups: list[str] | Unset = UNSET
    auto_approve: bool | Unset = False
    max_batch_pct: int | Unset = 20
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        schedule_cron = self.schedule_cron

        asset_groups: list[str] | Unset = UNSET
        if not isinstance(self.asset_groups, Unset):
            asset_groups = self.asset_groups

        auto_approve = self.auto_approve

        max_batch_pct = self.max_batch_pct

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if schedule_cron is not UNSET:
            field_dict["schedule_cron"] = schedule_cron
        if asset_groups is not UNSET:
            field_dict["asset_groups"] = asset_groups
        if auto_approve is not UNSET:
            field_dict["auto_approve"] = auto_approve
        if max_batch_pct is not UNSET:
            field_dict["max_batch_pct"] = max_batch_pct

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        schedule_cron = d.pop("schedule_cron", UNSET)

        asset_groups = cast(list[str], d.pop("asset_groups", UNSET))

        auto_approve = d.pop("auto_approve", UNSET)

        max_batch_pct = d.pop("max_batch_pct", UNSET)

        patch_window_in = cls(
            name=name,
            schedule_cron=schedule_cron,
            asset_groups=asset_groups,
            auto_approve=auto_approve,
            max_batch_pct=max_batch_pct,
        )

        patch_window_in.additional_properties = d
        return patch_window_in

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
