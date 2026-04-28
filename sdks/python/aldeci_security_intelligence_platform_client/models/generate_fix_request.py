from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GenerateFixRequest")


@_attrs_define
class GenerateFixRequest:
    """Request to generate fix.

    Attributes:
        finding_id (str):
        language (None | str | Unset):
        include_tests (bool | Unset):  Default: True.
    """

    finding_id: str
    language: None | str | Unset = UNSET
    include_tests: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        language: None | str | Unset
        if isinstance(self.language, Unset):
            language = UNSET
        else:
            language = self.language

        include_tests = self.include_tests

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
            }
        )
        if language is not UNSET:
            field_dict["language"] = language
        if include_tests is not UNSET:
            field_dict["include_tests"] = include_tests

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        def _parse_language(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        language = _parse_language(d.pop("language", UNSET))

        include_tests = d.pop("include_tests", UNSET)

        generate_fix_request = cls(
            finding_id=finding_id,
            language=language,
            include_tests=include_tests,
        )

        generate_fix_request.additional_properties = d
        return generate_fix_request

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
