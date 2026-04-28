from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EstablishBaselineRequest")


@_attrs_define
class EstablishBaselineRequest:
    """
    Attributes:
        user_id (str):
        org_id (str | Unset):  Default: 'default'.
        baseline_type (str | Unset):  Default: 'login_hours'.
        normal_value (float | Unset):  Default: 0.0.
        std_deviation (float | Unset):  Default: 0.0.
        samples_count (int | Unset):  Default: 0.
    """

    user_id: str
    org_id: str | Unset = "default"
    baseline_type: str | Unset = "login_hours"
    normal_value: float | Unset = 0.0
    std_deviation: float | Unset = 0.0
    samples_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        org_id = self.org_id

        baseline_type = self.baseline_type

        normal_value = self.normal_value

        std_deviation = self.std_deviation

        samples_count = self.samples_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if baseline_type is not UNSET:
            field_dict["baseline_type"] = baseline_type
        if normal_value is not UNSET:
            field_dict["normal_value"] = normal_value
        if std_deviation is not UNSET:
            field_dict["std_deviation"] = std_deviation
        if samples_count is not UNSET:
            field_dict["samples_count"] = samples_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        org_id = d.pop("org_id", UNSET)

        baseline_type = d.pop("baseline_type", UNSET)

        normal_value = d.pop("normal_value", UNSET)

        std_deviation = d.pop("std_deviation", UNSET)

        samples_count = d.pop("samples_count", UNSET)

        establish_baseline_request = cls(
            user_id=user_id,
            org_id=org_id,
            baseline_type=baseline_type,
            normal_value=normal_value,
            std_deviation=std_deviation,
            samples_count=samples_count,
        )

        establish_baseline_request.additional_properties = d
        return establish_baseline_request

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
