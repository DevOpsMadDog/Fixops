from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RawIngestIn")


@_attrs_define
class RawIngestIn:
    """
    Attributes:
        raw (str): Raw syslog (RFC 3164/5424) or CEF log line
        org_id (str | Unset):  Default: 'default'.
        format_ (str | Unset): 'syslog' | 'cef' | 'auto' (default — auto-detected from content) Default: 'auto'.
    """

    raw: str
    org_id: str | Unset = "default"
    format_: str | Unset = "auto"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        raw = self.raw

        org_id = self.org_id

        format_ = self.format_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "raw": raw,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if format_ is not UNSET:
            field_dict["format"] = format_

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        raw = d.pop("raw")

        org_id = d.pop("org_id", UNSET)

        format_ = d.pop("format", UNSET)

        raw_ingest_in = cls(
            raw=raw,
            org_id=org_id,
            format_=format_,
        )

        raw_ingest_in.additional_properties = d
        return raw_ingest_in

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
