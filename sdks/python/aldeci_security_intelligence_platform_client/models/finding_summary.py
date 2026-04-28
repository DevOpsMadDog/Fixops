from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FindingSummary")


@_attrs_define
class FindingSummary:
    """
    Attributes:
        id (str):
        check_id (str):
        title (str):
        severity (str):
        category (str):
        remediation (str):
        line_number (int | None | Unset):
    """

    id: str
    check_id: str
    title: str
    severity: str
    category: str
    remediation: str
    line_number: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        check_id = self.check_id

        title = self.title

        severity = self.severity

        category = self.category

        remediation = self.remediation

        line_number: int | None | Unset
        if isinstance(self.line_number, Unset):
            line_number = UNSET
        else:
            line_number = self.line_number

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "check_id": check_id,
                "title": title,
                "severity": severity,
                "category": category,
                "remediation": remediation,
            }
        )
        if line_number is not UNSET:
            field_dict["line_number"] = line_number

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        check_id = d.pop("check_id")

        title = d.pop("title")

        severity = d.pop("severity")

        category = d.pop("category")

        remediation = d.pop("remediation")

        def _parse_line_number(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        line_number = _parse_line_number(d.pop("line_number", UNSET))

        finding_summary = cls(
            id=id,
            check_id=check_id,
            title=title,
            severity=severity,
            category=category,
            remediation=remediation,
            line_number=line_number,
        )

        finding_summary.additional_properties = d
        return finding_summary

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
