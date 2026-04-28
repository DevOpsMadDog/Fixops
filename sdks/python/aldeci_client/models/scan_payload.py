from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanPayload")


@_attrs_define
class ScanPayload:
    """POST /scan — scan content or a virtual source for sensitive data.

    Attributes:
        content (None | str | Unset):
        source_type (str | Unset):  Default: 'file'.
        source_path (None | str | Unset):
        column_names (list[str] | None | Unset):
        deep_scan (bool | Unset):  Default: False.
    """

    content: None | str | Unset = UNSET
    source_type: str | Unset = "file"
    source_path: None | str | Unset = UNSET
    column_names: list[str] | None | Unset = UNSET
    deep_scan: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        content: None | str | Unset
        if isinstance(self.content, Unset):
            content = UNSET
        else:
            content = self.content

        source_type = self.source_type

        source_path: None | str | Unset
        if isinstance(self.source_path, Unset):
            source_path = UNSET
        else:
            source_path = self.source_path

        column_names: list[str] | None | Unset
        if isinstance(self.column_names, Unset):
            column_names = UNSET
        elif isinstance(self.column_names, list):
            column_names = self.column_names

        else:
            column_names = self.column_names

        deep_scan = self.deep_scan

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if content is not UNSET:
            field_dict["content"] = content
        if source_type is not UNSET:
            field_dict["source_type"] = source_type
        if source_path is not UNSET:
            field_dict["source_path"] = source_path
        if column_names is not UNSET:
            field_dict["column_names"] = column_names
        if deep_scan is not UNSET:
            field_dict["deep_scan"] = deep_scan

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_content(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        content = _parse_content(d.pop("content", UNSET))

        source_type = d.pop("source_type", UNSET)

        def _parse_source_path(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_path = _parse_source_path(d.pop("source_path", UNSET))

        def _parse_column_names(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                column_names_type_0 = cast(list[str], data)

                return column_names_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        column_names = _parse_column_names(d.pop("column_names", UNSET))

        deep_scan = d.pop("deep_scan", UNSET)

        scan_payload = cls(
            content=content,
            source_type=source_type,
            source_path=source_path,
            column_names=column_names,
            deep_scan=deep_scan,
        )

        scan_payload.additional_properties = d
        return scan_payload

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
