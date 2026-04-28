from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateTreatmentStatusRequest")


@_attrs_define
class UpdateTreatmentStatusRequest:
    """
    Attributes:
        status (str): planned | in_progress | completed | overdue
        completion_date (str | Unset): ISO date when completed Default: ''.
    """

    status: str
    completion_date: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        completion_date = self.completion_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
            }
        )
        if completion_date is not UNSET:
            field_dict["completion_date"] = completion_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = d.pop("status")

        completion_date = d.pop("completion_date", UNSET)

        update_treatment_status_request = cls(
            status=status,
            completion_date=completion_date,
        )

        update_treatment_status_request.additional_properties = d
        return update_treatment_status_request

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
