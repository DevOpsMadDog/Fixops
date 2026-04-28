from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="HealthCheckCreate")


@_attrs_define
class HealthCheckCreate:
    """
    Attributes:
        check_name (str):
        category (str | Unset):  Default: 'network'.
        status (str | Unset):  Default: 'unknown'.
        score (int | Unset):  Default: 0.
        details (str | Unset):  Default: ''.
        check_interval_hours (int | Unset):  Default: 24.
    """

    check_name: str
    category: str | Unset = "network"
    status: str | Unset = "unknown"
    score: int | Unset = 0
    details: str | Unset = ""
    check_interval_hours: int | Unset = 24
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        check_name = self.check_name

        category = self.category

        status = self.status

        score = self.score

        details = self.details

        check_interval_hours = self.check_interval_hours

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "check_name": check_name,
            }
        )
        if category is not UNSET:
            field_dict["category"] = category
        if status is not UNSET:
            field_dict["status"] = status
        if score is not UNSET:
            field_dict["score"] = score
        if details is not UNSET:
            field_dict["details"] = details
        if check_interval_hours is not UNSET:
            field_dict["check_interval_hours"] = check_interval_hours

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        check_name = d.pop("check_name")

        category = d.pop("category", UNSET)

        status = d.pop("status", UNSET)

        score = d.pop("score", UNSET)

        details = d.pop("details", UNSET)

        check_interval_hours = d.pop("check_interval_hours", UNSET)

        health_check_create = cls(
            check_name=check_name,
            category=category,
            status=status,
            score=score,
            details=details,
            check_interval_hours=check_interval_hours,
        )

        health_check_create.additional_properties = d
        return health_check_create

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
