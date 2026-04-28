from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SampleSubmit")


@_attrs_define
class SampleSubmit:
    """
    Attributes:
        sha256 (str):
        file_name (str | Unset):  Default: ''.
        file_type (str | Unset):  Default: ''.
        file_size (int | Unset):  Default: 0.
        source (str | Unset):  Default: ''.
    """

    sha256: str
    file_name: str | Unset = ""
    file_type: str | Unset = ""
    file_size: int | Unset = 0
    source: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        sha256 = self.sha256

        file_name = self.file_name

        file_type = self.file_type

        file_size = self.file_size

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "sha256": sha256,
            }
        )
        if file_name is not UNSET:
            field_dict["file_name"] = file_name
        if file_type is not UNSET:
            field_dict["file_type"] = file_type
        if file_size is not UNSET:
            field_dict["file_size"] = file_size
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        sha256 = d.pop("sha256")

        file_name = d.pop("file_name", UNSET)

        file_type = d.pop("file_type", UNSET)

        file_size = d.pop("file_size", UNSET)

        source = d.pop("source", UNSET)

        sample_submit = cls(
            sha256=sha256,
            file_name=file_name,
            file_type=file_type,
            file_size=file_size,
            source=source,
        )

        sample_submit.additional_properties = d
        return sample_submit

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
