from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DraftExceptionBody")


@_attrs_define
class DraftExceptionBody:
    """
    Attributes:
        finding_id (str):
        business_justification (str | Unset):  Default: ''.
    """

    finding_id: str
    business_justification: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        business_justification = self.business_justification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
            }
        )
        if business_justification is not UNSET:
            field_dict["business_justification"] = business_justification

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        business_justification = d.pop("business_justification", UNSET)

        draft_exception_body = cls(
            finding_id=finding_id,
            business_justification=business_justification,
        )

        draft_exception_body.additional_properties = d
        return draft_exception_body

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
