from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.subsystem_status import SubsystemStatus


T = TypeVar("T", bound="ProbeResult")


@_attrs_define
class ProbeResult:
    """Result of a health probe check.

    Attributes:
        status (str):
        timestamp (str):
        checks (list[SubsystemStatus] | Unset):
        uptime_seconds (float | Unset):  Default: 0.0.
    """

    status: str
    timestamp: str
    checks: list[SubsystemStatus] | Unset = UNSET
    uptime_seconds: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        timestamp = self.timestamp

        checks: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.checks, Unset):
            checks = []
            for checks_item_data in self.checks:
                checks_item = checks_item_data.to_dict()
                checks.append(checks_item)

        uptime_seconds = self.uptime_seconds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
                "timestamp": timestamp,
            }
        )
        if checks is not UNSET:
            field_dict["checks"] = checks
        if uptime_seconds is not UNSET:
            field_dict["uptime_seconds"] = uptime_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.subsystem_status import SubsystemStatus

        d = dict(src_dict)
        status = d.pop("status")

        timestamp = d.pop("timestamp")

        _checks = d.pop("checks", UNSET)
        checks: list[SubsystemStatus] | Unset = UNSET
        if _checks is not UNSET:
            checks = []
            for checks_item_data in _checks:
                checks_item = SubsystemStatus.from_dict(checks_item_data)

                checks.append(checks_item)

        uptime_seconds = d.pop("uptime_seconds", UNSET)

        probe_result = cls(
            status=status,
            timestamp=timestamp,
            checks=checks,
            uptime_seconds=uptime_seconds,
        )

        probe_result.additional_properties = d
        return probe_result

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
