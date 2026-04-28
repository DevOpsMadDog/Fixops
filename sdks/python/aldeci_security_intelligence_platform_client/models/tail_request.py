from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TailRequest")


@_attrs_define
class TailRequest:
    """
    Attributes:
        file_paths (list[str]): Absolute paths to log files to tail (e.g. /var/log/system.log).
        org_id (str | Unset): Tenant identifier Default: 'default'.
        format_ (str | Unset): Adapter key per file (auto picks json_lines for JSON-leading lines, syslog otherwise).
            Default: 'auto'.
        max_bytes_per_file (int | Unset):  Default: 1048576.
        max_lines_per_file (int | Unset):  Default: 5000.
    """

    file_paths: list[str]
    org_id: str | Unset = "default"
    format_: str | Unset = "auto"
    max_bytes_per_file: int | Unset = 1048576
    max_lines_per_file: int | Unset = 5000
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file_paths = self.file_paths

        org_id = self.org_id

        format_ = self.format_

        max_bytes_per_file = self.max_bytes_per_file

        max_lines_per_file = self.max_lines_per_file

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "file_paths": file_paths,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if format_ is not UNSET:
            field_dict["format"] = format_
        if max_bytes_per_file is not UNSET:
            field_dict["max_bytes_per_file"] = max_bytes_per_file
        if max_lines_per_file is not UNSET:
            field_dict["max_lines_per_file"] = max_lines_per_file

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        file_paths = cast(list[str], d.pop("file_paths"))

        org_id = d.pop("org_id", UNSET)

        format_ = d.pop("format", UNSET)

        max_bytes_per_file = d.pop("max_bytes_per_file", UNSET)

        max_lines_per_file = d.pop("max_lines_per_file", UNSET)

        tail_request = cls(
            file_paths=file_paths,
            org_id=org_id,
            format_=format_,
            max_bytes_per_file=max_bytes_per_file,
            max_lines_per_file=max_lines_per_file,
        )

        tail_request.additional_properties = d
        return tail_request

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
