from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SLAPolicySet")


@_attrs_define
class SLAPolicySet:
    """
    Attributes:
        org_id (str):
        severity (str):
        max_days (int | Unset):  Default: 30.
    """

    org_id: str
    severity: str
    max_days: int | Unset = 30
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        severity = self.severity

        max_days = self.max_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "severity": severity,
            }
        )
        if max_days is not UNSET:
            field_dict["max_days"] = max_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        severity = d.pop("severity")

        max_days = d.pop("max_days", UNSET)

        sla_policy_set = cls(
            org_id=org_id,
            severity=severity,
            max_days=max_days,
        )

        sla_policy_set.additional_properties = d
        return sla_policy_set

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
