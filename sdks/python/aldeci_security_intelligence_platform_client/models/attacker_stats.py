from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.attacker_stats_categories import AttackerStatsCategories


T = TypeVar("T", bound="AttackerStats")


@_attrs_define
class AttackerStats:
    """Per-IP attacker summary.

    Attributes:
        ip (str):
        total_threats (int):
        categories (AttackerStatsCategories):
        first_seen (datetime.datetime):
        last_seen (datetime.datetime):
        is_blocked (bool):
        block_expires_at (datetime.datetime | None | Unset):
    """

    ip: str
    total_threats: int
    categories: AttackerStatsCategories
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    is_blocked: bool
    block_expires_at: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ip = self.ip

        total_threats = self.total_threats

        categories = self.categories.to_dict()

        first_seen = self.first_seen.isoformat()

        last_seen = self.last_seen.isoformat()

        is_blocked = self.is_blocked

        block_expires_at: None | str | Unset
        if isinstance(self.block_expires_at, Unset):
            block_expires_at = UNSET
        elif isinstance(self.block_expires_at, datetime.datetime):
            block_expires_at = self.block_expires_at.isoformat()
        else:
            block_expires_at = self.block_expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ip": ip,
                "total_threats": total_threats,
                "categories": categories,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "is_blocked": is_blocked,
            }
        )
        if block_expires_at is not UNSET:
            field_dict["block_expires_at"] = block_expires_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.attacker_stats_categories import AttackerStatsCategories

        d = dict(src_dict)
        ip = d.pop("ip")

        total_threats = d.pop("total_threats")

        categories = AttackerStatsCategories.from_dict(d.pop("categories"))

        first_seen = isoparse(d.pop("first_seen"))

        last_seen = isoparse(d.pop("last_seen"))

        is_blocked = d.pop("is_blocked")

        def _parse_block_expires_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                block_expires_at_type_0 = isoparse(data)

                return block_expires_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        block_expires_at = _parse_block_expires_at(d.pop("block_expires_at", UNSET))

        attacker_stats = cls(
            ip=ip,
            total_threats=total_threats,
            categories=categories,
            first_seen=first_seen,
            last_seen=last_seen,
            is_blocked=is_blocked,
            block_expires_at=block_expires_at,
        )

        attacker_stats.additional_properties = d
        return attacker_stats

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
