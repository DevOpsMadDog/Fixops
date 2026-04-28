from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CheckRequest")


@_attrs_define
class CheckRequest:
    """
    Attributes:
        check_ref (str):
        title (str):
        description (str | Unset):  Default: ''.
        category (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        expected_value (str | Unset):  Default: ''.
        remediation (str | Unset):  Default: ''.
    """

    check_ref: str
    title: str
    description: str | Unset = ""
    category: str | Unset = ""
    severity: str | Unset = "medium"
    expected_value: str | Unset = ""
    remediation: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        check_ref = self.check_ref

        title = self.title

        description = self.description

        category = self.category

        severity = self.severity

        expected_value = self.expected_value

        remediation = self.remediation

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "check_ref": check_ref,
                "title": title,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if category is not UNSET:
            field_dict["category"] = category
        if severity is not UNSET:
            field_dict["severity"] = severity
        if expected_value is not UNSET:
            field_dict["expected_value"] = expected_value
        if remediation is not UNSET:
            field_dict["remediation"] = remediation

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        check_ref = d.pop("check_ref")

        title = d.pop("title")

        description = d.pop("description", UNSET)

        category = d.pop("category", UNSET)

        severity = d.pop("severity", UNSET)

        expected_value = d.pop("expected_value", UNSET)

        remediation = d.pop("remediation", UNSET)

        check_request = cls(
            check_ref=check_ref,
            title=title,
            description=description,
            category=category,
            severity=severity,
            expected_value=expected_value,
            remediation=remediation,
        )

        check_request.additional_properties = d
        return check_request

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
