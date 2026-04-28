from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanCodeRequest")


@_attrs_define
class ScanCodeRequest:
    """
    Attributes:
        code (str): Source code to scan
        filename (str | Unset): Filename for language detection Default: 'input.py'.
        language (str | Unset): Language hint (optional)
        app_id (str | Unset): Application ID (optional)
    """

    code: str
    filename: str | Unset = "input.py"
    language: str | Unset = UNSET
    app_id: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        code = self.code

        filename = self.filename

        language = self.language

        app_id = self.app_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "code": code,
            }
        )
        if filename is not UNSET:
            field_dict["filename"] = filename
        if language is not UNSET:
            field_dict["language"] = language
        if app_id is not UNSET:
            field_dict["app_id"] = app_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        code = d.pop("code")

        filename = d.pop("filename", UNSET)

        language = d.pop("language", UNSET)

        app_id = d.pop("app_id", UNSET)

        scan_code_request = cls(
            code=code,
            filename=filename,
            language=language,
            app_id=app_id,
        )

        scan_code_request.additional_properties = d
        return scan_code_request

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
