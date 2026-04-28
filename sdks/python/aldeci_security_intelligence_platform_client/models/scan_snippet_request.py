from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanSnippetRequest")


@_attrs_define
class ScanSnippetRequest:
    """
    Attributes:
        code (str): Source code snippet to scan.
        language (str): Language name (python/javascript/typescript/go/java/ruby/php/c/cpp/rust/csharp).
        source_hint (str | Unset): Provenance tag: ai_generated|copilot|claude|cursor|manual|unknown. Default:
            'ai_generated'.
    """

    code: str
    language: str
    source_hint: str | Unset = "ai_generated"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        code = self.code

        language = self.language

        source_hint = self.source_hint

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "code": code,
                "language": language,
            }
        )
        if source_hint is not UNSET:
            field_dict["source_hint"] = source_hint

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        code = d.pop("code")

        language = d.pop("language")

        source_hint = d.pop("source_hint", UNSET)

        scan_snippet_request = cls(
            code=code,
            language=language,
            source_hint=source_hint,
        )

        scan_snippet_request.additional_properties = d
        return scan_snippet_request

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
