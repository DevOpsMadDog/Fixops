from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SLAConfigCreate")


@_attrs_define
class SLAConfigCreate:
    """
    Attributes:
        severity (str):
        response_sla_minutes (int | Unset):  Default: 60.
        containment_sla_minutes (int | Unset):  Default: 240.
        resolution_sla_minutes (int | Unset):  Default: 1440.
    """

    severity: str
    response_sla_minutes: int | Unset = 60
    containment_sla_minutes: int | Unset = 240
    resolution_sla_minutes: int | Unset = 1440
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        severity = self.severity

        response_sla_minutes = self.response_sla_minutes

        containment_sla_minutes = self.containment_sla_minutes

        resolution_sla_minutes = self.resolution_sla_minutes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "severity": severity,
            }
        )
        if response_sla_minutes is not UNSET:
            field_dict["response_sla_minutes"] = response_sla_minutes
        if containment_sla_minutes is not UNSET:
            field_dict["containment_sla_minutes"] = containment_sla_minutes
        if resolution_sla_minutes is not UNSET:
            field_dict["resolution_sla_minutes"] = resolution_sla_minutes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        severity = d.pop("severity")

        response_sla_minutes = d.pop("response_sla_minutes", UNSET)

        containment_sla_minutes = d.pop("containment_sla_minutes", UNSET)

        resolution_sla_minutes = d.pop("resolution_sla_minutes", UNSET)

        sla_config_create = cls(
            severity=severity,
            response_sla_minutes=response_sla_minutes,
            containment_sla_minutes=containment_sla_minutes,
            resolution_sla_minutes=resolution_sla_minutes,
        )

        sla_config_create.additional_properties = d
        return sla_config_create

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
