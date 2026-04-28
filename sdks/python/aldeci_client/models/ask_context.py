from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AskContext")


@_attrs_define
class AskContext:
    """Optional context supplied alongside the free-text question.

    Attributes:
        finding_id (None | str | Unset): Associated finding ID
        language (None | str | Unset): Programming language (e.g. 'python')
        cwe_id (None | str | Unset): CWE identifier hint, e.g. 'CWE-89'
    """

    finding_id: None | str | Unset = UNSET
    language: None | str | Unset = UNSET
    cwe_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id: None | str | Unset
        if isinstance(self.finding_id, Unset):
            finding_id = UNSET
        else:
            finding_id = self.finding_id

        language: None | str | Unset
        if isinstance(self.language, Unset):
            language = UNSET
        else:
            language = self.language

        cwe_id: None | str | Unset
        if isinstance(self.cwe_id, Unset):
            cwe_id = UNSET
        else:
            cwe_id = self.cwe_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if finding_id is not UNSET:
            field_dict["finding_id"] = finding_id
        if language is not UNSET:
            field_dict["language"] = language
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_finding_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        finding_id = _parse_finding_id(d.pop("finding_id", UNSET))

        def _parse_language(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        language = _parse_language(d.pop("language", UNSET))

        def _parse_cwe_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cwe_id = _parse_cwe_id(d.pop("cwe_id", UNSET))

        ask_context = cls(
            finding_id=finding_id,
            language=language,
            cwe_id=cwe_id,
        )

        ask_context.additional_properties = d
        return ask_context

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
