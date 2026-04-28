from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MPTERetestRequest")


@_attrs_define
class MPTERetestRequest:
    """Request body for POST /api/v1/verify/mpte-retest.

    Re-runs only the MPTE exploit simulation against the fixed code.

        Attributes:
            original_code (str):
            fixed_code (str):
            language (str):
            finding_type (str):
            finding_id (str | Unset):  Default: ''.
    """

    original_code: str
    fixed_code: str
    language: str
    finding_type: str
    finding_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        original_code = self.original_code

        fixed_code = self.fixed_code

        language = self.language

        finding_type = self.finding_type

        finding_id = self.finding_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "original_code": original_code,
                "fixed_code": fixed_code,
                "language": language,
                "finding_type": finding_type,
            }
        )
        if finding_id is not UNSET:
            field_dict["finding_id"] = finding_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        original_code = d.pop("original_code")

        fixed_code = d.pop("fixed_code")

        language = d.pop("language")

        finding_type = d.pop("finding_type")

        finding_id = d.pop("finding_id", UNSET)

        mpte_retest_request = cls(
            original_code=original_code,
            fixed_code=fixed_code,
            language=language,
            finding_type=finding_type,
            finding_id=finding_id,
        )

        mpte_retest_request.additional_properties = d
        return mpte_retest_request

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
