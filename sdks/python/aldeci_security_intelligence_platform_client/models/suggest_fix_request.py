from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SuggestFixRequest")


@_attrs_define
class SuggestFixRequest:
    """Request to get a code fix suggestion.

    Attributes:
        id (str):
        cwe_id (str):
        code_snippet (str | Unset):  Default: ''.
    """

    id: str
    cwe_id: str
    code_snippet: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        cwe_id = self.cwe_id

        code_snippet = self.code_snippet

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "cwe_id": cwe_id,
            }
        )
        if code_snippet is not UNSET:
            field_dict["code_snippet"] = code_snippet

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        cwe_id = d.pop("cwe_id")

        code_snippet = d.pop("code_snippet", UNSET)

        suggest_fix_request = cls(
            id=id,
            cwe_id=cwe_id,
            code_snippet=code_snippet,
        )

        suggest_fix_request.additional_properties = d
        return suggest_fix_request

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
