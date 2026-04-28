from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GeneratePocRequest")


@_attrs_define
class GeneratePocRequest:
    """Request to generate proof-of-concept.

    Attributes:
        cve_id (str):
        language (str | Unset): python, go, bash Default: 'python'.
        safe_poc (bool | Unset):  Default: True.
    """

    cve_id: str
    language: str | Unset = "python"
    safe_poc: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        language = self.language

        safe_poc = self.safe_poc

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if language is not UNSET:
            field_dict["language"] = language
        if safe_poc is not UNSET:
            field_dict["safe_poc"] = safe_poc

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        language = d.pop("language", UNSET)

        safe_poc = d.pop("safe_poc", UNSET)

        generate_poc_request = cls(
            cve_id=cve_id,
            language=language,
            safe_poc=safe_poc,
        )

        generate_poc_request.additional_properties = d
        return generate_poc_request

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
