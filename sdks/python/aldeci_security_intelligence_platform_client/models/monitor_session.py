from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MonitorSession")


@_attrs_define
class MonitorSession:
    """
    Attributes:
        target (str):
        id (str | Unset):
        interval_seconds (int | Unset):  Default: 300.
        started_at (str | Unset):
        last_snapshot_id (None | str | Unset):
        snapshot_count (int | Unset):  Default: 0.
        active (bool | Unset):  Default: True.
    """

    target: str
    id: str | Unset = UNSET
    interval_seconds: int | Unset = 300
    started_at: str | Unset = UNSET
    last_snapshot_id: None | str | Unset = UNSET
    snapshot_count: int | Unset = 0
    active: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target = self.target

        id = self.id

        interval_seconds = self.interval_seconds

        started_at = self.started_at

        last_snapshot_id: None | str | Unset
        if isinstance(self.last_snapshot_id, Unset):
            last_snapshot_id = UNSET
        else:
            last_snapshot_id = self.last_snapshot_id

        snapshot_count = self.snapshot_count

        active = self.active

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "target": target,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if interval_seconds is not UNSET:
            field_dict["interval_seconds"] = interval_seconds
        if started_at is not UNSET:
            field_dict["started_at"] = started_at
        if last_snapshot_id is not UNSET:
            field_dict["last_snapshot_id"] = last_snapshot_id
        if snapshot_count is not UNSET:
            field_dict["snapshot_count"] = snapshot_count
        if active is not UNSET:
            field_dict["active"] = active

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target = d.pop("target")

        id = d.pop("id", UNSET)

        interval_seconds = d.pop("interval_seconds", UNSET)

        started_at = d.pop("started_at", UNSET)

        def _parse_last_snapshot_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_snapshot_id = _parse_last_snapshot_id(d.pop("last_snapshot_id", UNSET))

        snapshot_count = d.pop("snapshot_count", UNSET)

        active = d.pop("active", UNSET)

        monitor_session = cls(
            target=target,
            id=id,
            interval_seconds=interval_seconds,
            started_at=started_at,
            last_snapshot_id=last_snapshot_id,
            snapshot_count=snapshot_count,
            active=active,
        )

        monitor_session.additional_properties = d
        return monitor_session

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
