from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SASTFindingCreate")


@_attrs_define
class SASTFindingCreate:
    """
    Attributes:
        title (str):
        tool (str | Unset):  Default: 'bandit'.
        rule_id (str | Unset):  Default: ''.
        category (str | Unset):  Default: 'injection'.
        severity (str | Unset):  Default: 'medium'.
        file_path (str | Unset):  Default: ''.
        line_number (int | Unset):  Default: 0.
        code_snippet (str | Unset):  Default: ''.
        cwe_id (str | Unset):  Default: ''.
    """

    title: str
    tool: str | Unset = "bandit"
    rule_id: str | Unset = ""
    category: str | Unset = "injection"
    severity: str | Unset = "medium"
    file_path: str | Unset = ""
    line_number: int | Unset = 0
    code_snippet: str | Unset = ""
    cwe_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        tool = self.tool

        rule_id = self.rule_id

        category = self.category

        severity = self.severity

        file_path = self.file_path

        line_number = self.line_number

        code_snippet = self.code_snippet

        cwe_id = self.cwe_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if tool is not UNSET:
            field_dict["tool"] = tool
        if rule_id is not UNSET:
            field_dict["rule_id"] = rule_id
        if category is not UNSET:
            field_dict["category"] = category
        if severity is not UNSET:
            field_dict["severity"] = severity
        if file_path is not UNSET:
            field_dict["file_path"] = file_path
        if line_number is not UNSET:
            field_dict["line_number"] = line_number
        if code_snippet is not UNSET:
            field_dict["code_snippet"] = code_snippet
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        tool = d.pop("tool", UNSET)

        rule_id = d.pop("rule_id", UNSET)

        category = d.pop("category", UNSET)

        severity = d.pop("severity", UNSET)

        file_path = d.pop("file_path", UNSET)

        line_number = d.pop("line_number", UNSET)

        code_snippet = d.pop("code_snippet", UNSET)

        cwe_id = d.pop("cwe_id", UNSET)

        sast_finding_create = cls(
            title=title,
            tool=tool,
            rule_id=rule_id,
            category=category,
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=cwe_id,
        )

        sast_finding_create.additional_properties = d
        return sast_finding_create

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
