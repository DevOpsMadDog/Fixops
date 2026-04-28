from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Finding")


@_attrs_define
class Finding:
    """Code analysis finding.

    Attributes:
        rule_id (str):
        message (str):
        severity (str):
        category (str):
        line (int):
        column (int):
        end_line (int | None | Unset):
        end_column (int | None | Unset):
        cwe_id (None | str | Unset):
        fix_suggestion (None | str | Unset):
        code_snippet (None | str | Unset):
    """

    rule_id: str
    message: str
    severity: str
    category: str
    line: int
    column: int
    end_line: int | None | Unset = UNSET
    end_column: int | None | Unset = UNSET
    cwe_id: None | str | Unset = UNSET
    fix_suggestion: None | str | Unset = UNSET
    code_snippet: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_id = self.rule_id

        message = self.message

        severity = self.severity

        category = self.category

        line = self.line

        column = self.column

        end_line: int | None | Unset
        if isinstance(self.end_line, Unset):
            end_line = UNSET
        else:
            end_line = self.end_line

        end_column: int | None | Unset
        if isinstance(self.end_column, Unset):
            end_column = UNSET
        else:
            end_column = self.end_column

        cwe_id: None | str | Unset
        if isinstance(self.cwe_id, Unset):
            cwe_id = UNSET
        else:
            cwe_id = self.cwe_id

        fix_suggestion: None | str | Unset
        if isinstance(self.fix_suggestion, Unset):
            fix_suggestion = UNSET
        else:
            fix_suggestion = self.fix_suggestion

        code_snippet: None | str | Unset
        if isinstance(self.code_snippet, Unset):
            code_snippet = UNSET
        else:
            code_snippet = self.code_snippet

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_id": rule_id,
                "message": message,
                "severity": severity,
                "category": category,
                "line": line,
                "column": column,
            }
        )
        if end_line is not UNSET:
            field_dict["end_line"] = end_line
        if end_column is not UNSET:
            field_dict["end_column"] = end_column
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id
        if fix_suggestion is not UNSET:
            field_dict["fix_suggestion"] = fix_suggestion
        if code_snippet is not UNSET:
            field_dict["code_snippet"] = code_snippet

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rule_id = d.pop("rule_id")

        message = d.pop("message")

        severity = d.pop("severity")

        category = d.pop("category")

        line = d.pop("line")

        column = d.pop("column")

        def _parse_end_line(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        end_line = _parse_end_line(d.pop("end_line", UNSET))

        def _parse_end_column(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        end_column = _parse_end_column(d.pop("end_column", UNSET))

        def _parse_cwe_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cwe_id = _parse_cwe_id(d.pop("cwe_id", UNSET))

        def _parse_fix_suggestion(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fix_suggestion = _parse_fix_suggestion(d.pop("fix_suggestion", UNSET))

        def _parse_code_snippet(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        code_snippet = _parse_code_snippet(d.pop("code_snippet", UNSET))

        finding = cls(
            rule_id=rule_id,
            message=message,
            severity=severity,
            category=category,
            line=line,
            column=column,
            end_line=end_line,
            end_column=end_column,
            cwe_id=cwe_id,
            fix_suggestion=fix_suggestion,
            code_snippet=code_snippet,
        )

        finding.additional_properties = d
        return finding

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
