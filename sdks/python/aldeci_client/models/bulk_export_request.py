from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BulkExportRequest")


@_attrs_define
class BulkExportRequest:
    """Request model for bulk export.

    Attributes:
        ids (list[str]):
        org_id (str):
        format_ (str | Unset):  Default: 'json'.
        include_fields (list[str] | None | Unset):
    """

    ids: list[str]
    org_id: str
    format_: str | Unset = "json"
    include_fields: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ids = self.ids

        org_id = self.org_id

        format_ = self.format_

        include_fields: list[str] | None | Unset
        if isinstance(self.include_fields, Unset):
            include_fields = UNSET
        elif isinstance(self.include_fields, list):
            include_fields = self.include_fields

        else:
            include_fields = self.include_fields

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ids": ids,
                "org_id": org_id,
            }
        )
        if format_ is not UNSET:
            field_dict["format"] = format_
        if include_fields is not UNSET:
            field_dict["include_fields"] = include_fields

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ids = cast(list[str], d.pop("ids"))

        org_id = d.pop("org_id")

        format_ = d.pop("format", UNSET)

        def _parse_include_fields(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                include_fields_type_0 = cast(list[str], data)

                return include_fields_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        include_fields = _parse_include_fields(d.pop("include_fields", UNSET))

        bulk_export_request = cls(
            ids=ids,
            org_id=org_id,
            format_=format_,
            include_fields=include_fields,
        )

        bulk_export_request.additional_properties = d
        return bulk_export_request

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
