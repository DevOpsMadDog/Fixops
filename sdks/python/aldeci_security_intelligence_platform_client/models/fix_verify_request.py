from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FixVerifyRequest")


@_attrs_define
class FixVerifyRequest:
    """Request to verify a proposed auto-fix.

    Attributes:
        original_code (str): Original vulnerable code
        fixed_code (str): Proposed fixed code
        language (str): Programming language (python, javascript, java, go)
        finding_id (None | str | Unset): ID of the finding being fixed
        finding_title (None | str | Unset): Title of the finding
    """

    original_code: str
    fixed_code: str
    language: str
    finding_id: None | str | Unset = UNSET
    finding_title: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        original_code = self.original_code

        fixed_code = self.fixed_code

        language = self.language

        finding_id: None | str | Unset
        if isinstance(self.finding_id, Unset):
            finding_id = UNSET
        else:
            finding_id = self.finding_id

        finding_title: None | str | Unset
        if isinstance(self.finding_title, Unset):
            finding_title = UNSET
        else:
            finding_title = self.finding_title

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "original_code": original_code,
                "fixed_code": fixed_code,
                "language": language,
            }
        )
        if finding_id is not UNSET:
            field_dict["finding_id"] = finding_id
        if finding_title is not UNSET:
            field_dict["finding_title"] = finding_title

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        original_code = d.pop("original_code")

        fixed_code = d.pop("fixed_code")

        language = d.pop("language")

        def _parse_finding_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        finding_id = _parse_finding_id(d.pop("finding_id", UNSET))

        def _parse_finding_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        finding_title = _parse_finding_title(d.pop("finding_title", UNSET))

        fix_verify_request = cls(
            original_code=original_code,
            fixed_code=fixed_code,
            language=language,
            finding_id=finding_id,
            finding_title=finding_title,
        )

        fix_verify_request.additional_properties = d
        return fix_verify_request

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
