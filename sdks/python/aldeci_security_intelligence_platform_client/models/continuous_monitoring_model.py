from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ContinuousMonitoringModel")


@_attrs_define
class ContinuousMonitoringModel:
    """Model for continuous monitoring setup.

    Attributes:
        targets (list[str]):
        interval_minutes (int | Unset):  Default: 60.
    """

    targets: list[str]
    interval_minutes: int | Unset = 60
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        targets = self.targets

        interval_minutes = self.interval_minutes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "targets": targets,
            }
        )
        if interval_minutes is not UNSET:
            field_dict["interval_minutes"] = interval_minutes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        targets = cast(list[str], d.pop("targets"))

        interval_minutes = d.pop("interval_minutes", UNSET)

        continuous_monitoring_model = cls(
            targets=targets,
            interval_minutes=interval_minutes,
        )

        continuous_monitoring_model.additional_properties = d
        return continuous_monitoring_model

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
