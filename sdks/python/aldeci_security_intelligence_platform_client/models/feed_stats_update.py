from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FeedStatsUpdate")


@_attrs_define
class FeedStatsUpdate:
    """
    Attributes:
        ioc_count_delta (int | Unset): Increment ioc_count by this value Default: 0.
        last_polled (None | str | Unset):
    """

    ioc_count_delta: int | Unset = 0
    last_polled: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ioc_count_delta = self.ioc_count_delta

        last_polled: None | str | Unset
        if isinstance(self.last_polled, Unset):
            last_polled = UNSET
        else:
            last_polled = self.last_polled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if ioc_count_delta is not UNSET:
            field_dict["ioc_count_delta"] = ioc_count_delta
        if last_polled is not UNSET:
            field_dict["last_polled"] = last_polled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ioc_count_delta = d.pop("ioc_count_delta", UNSET)

        def _parse_last_polled(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_polled = _parse_last_polled(d.pop("last_polled", UNSET))

        feed_stats_update = cls(
            ioc_count_delta=ioc_count_delta,
            last_polled=last_polled,
        )

        feed_stats_update.additional_properties = d
        return feed_stats_update

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
