from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GapInput")


@_attrs_define
class GapInput:
    """
    Attributes:
        control_id (str):
        control_name (str):
        gap_description (str):
        findings_that_fix (list[str] | Unset):
    """

    control_id: str
    control_name: str
    gap_description: str
    findings_that_fix: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_id = self.control_id

        control_name = self.control_name

        gap_description = self.gap_description

        findings_that_fix: list[str] | Unset = UNSET
        if not isinstance(self.findings_that_fix, Unset):
            findings_that_fix = self.findings_that_fix

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_id": control_id,
                "control_name": control_name,
                "gap_description": gap_description,
            }
        )
        if findings_that_fix is not UNSET:
            field_dict["findings_that_fix"] = findings_that_fix

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_id = d.pop("control_id")

        control_name = d.pop("control_name")

        gap_description = d.pop("gap_description")

        findings_that_fix = cast(list[str], d.pop("findings_that_fix", UNSET))

        gap_input = cls(
            control_id=control_id,
            control_name=control_name,
            gap_description=gap_description,
            findings_that_fix=findings_that_fix,
        )

        gap_input.additional_properties = d
        return gap_input

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
