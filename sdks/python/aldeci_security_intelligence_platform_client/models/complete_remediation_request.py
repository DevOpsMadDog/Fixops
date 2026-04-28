from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CompleteRemediationRequest")


@_attrs_define
class CompleteRemediationRequest:
    """
    Attributes:
        org_id (str): Organisation ID
        actual_days (int | Unset): Actual days taken Default: 0.
    """

    org_id: str
    actual_days: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        actual_days = self.actual_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if actual_days is not UNSET:
            field_dict["actual_days"] = actual_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        actual_days = d.pop("actual_days", UNSET)

        complete_remediation_request = cls(
            org_id=org_id,
            actual_days=actual_days,
        )

        complete_remediation_request.additional_properties = d
        return complete_remediation_request

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
