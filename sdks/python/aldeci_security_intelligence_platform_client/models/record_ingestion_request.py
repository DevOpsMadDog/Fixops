from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordIngestionRequest")


@_attrs_define
class RecordIngestionRequest:
    """
    Attributes:
        iocs_fetched (int | Unset):  Default: 0.
        iocs_new (int | Unset):  Default: 0.
        iocs_updated (int | Unset):  Default: 0.
        status (str | Unset):  Default: 'success'.
        error_message (str | Unset):  Default: ''.
    """

    iocs_fetched: int | Unset = 0
    iocs_new: int | Unset = 0
    iocs_updated: int | Unset = 0
    status: str | Unset = "success"
    error_message: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        iocs_fetched = self.iocs_fetched

        iocs_new = self.iocs_new

        iocs_updated = self.iocs_updated

        status = self.status

        error_message = self.error_message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if iocs_fetched is not UNSET:
            field_dict["iocs_fetched"] = iocs_fetched
        if iocs_new is not UNSET:
            field_dict["iocs_new"] = iocs_new
        if iocs_updated is not UNSET:
            field_dict["iocs_updated"] = iocs_updated
        if status is not UNSET:
            field_dict["status"] = status
        if error_message is not UNSET:
            field_dict["error_message"] = error_message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        iocs_fetched = d.pop("iocs_fetched", UNSET)

        iocs_new = d.pop("iocs_new", UNSET)

        iocs_updated = d.pop("iocs_updated", UNSET)

        status = d.pop("status", UNSET)

        error_message = d.pop("error_message", UNSET)

        record_ingestion_request = cls(
            iocs_fetched=iocs_fetched,
            iocs_new=iocs_new,
            iocs_updated=iocs_updated,
            status=status,
            error_message=error_message,
        )

        record_ingestion_request.additional_properties = d
        return record_ingestion_request

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
