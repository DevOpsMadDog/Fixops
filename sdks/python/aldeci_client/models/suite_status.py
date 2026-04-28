from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SuiteStatus")


@_attrs_define
class SuiteStatus:
    """
    Attributes:
        suite (str):
        status (str):
        endpoints (int):
        latency_ms (float):
        last_heartbeat (str):
        active_tasks (int | Unset):  Default: 0.
    """

    suite: str
    status: str
    endpoints: int
    latency_ms: float
    last_heartbeat: str
    active_tasks: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        suite = self.suite

        status = self.status

        endpoints = self.endpoints

        latency_ms = self.latency_ms

        last_heartbeat = self.last_heartbeat

        active_tasks = self.active_tasks

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "suite": suite,
                "status": status,
                "endpoints": endpoints,
                "latency_ms": latency_ms,
                "last_heartbeat": last_heartbeat,
            }
        )
        if active_tasks is not UNSET:
            field_dict["active_tasks"] = active_tasks

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        suite = d.pop("suite")

        status = d.pop("status")

        endpoints = d.pop("endpoints")

        latency_ms = d.pop("latency_ms")

        last_heartbeat = d.pop("last_heartbeat")

        active_tasks = d.pop("active_tasks", UNSET)

        suite_status = cls(
            suite=suite,
            status=status,
            endpoints=endpoints,
            latency_ms=latency_ms,
            last_heartbeat=last_heartbeat,
            active_tasks=active_tasks,
        )

        suite_status.additional_properties = d
        return suite_status

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
