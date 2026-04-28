from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IngestRawRequest")


@_attrs_define
class IngestRawRequest:
    """Ingest a raw JSON-encoded dump (string body).

    Useful for clients that already have the raw API response and don't want
    to re-parse it client-side.

        Attributes:
            raw_json (str):
            org_id (str | Unset):  Default: 'default'.
            scan_id (None | str | Unset):
    """

    raw_json: str
    org_id: str | Unset = "default"
    scan_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        raw_json = self.raw_json

        org_id = self.org_id

        scan_id: None | str | Unset
        if isinstance(self.scan_id, Unset):
            scan_id = UNSET
        else:
            scan_id = self.scan_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "raw_json": raw_json,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if scan_id is not UNSET:
            field_dict["scan_id"] = scan_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        raw_json = d.pop("raw_json")

        org_id = d.pop("org_id", UNSET)

        def _parse_scan_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scan_id = _parse_scan_id(d.pop("scan_id", UNSET))

        ingest_raw_request = cls(
            raw_json=raw_json,
            org_id=org_id,
            scan_id=scan_id,
        )

        ingest_raw_request.additional_properties = d
        return ingest_raw_request

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
