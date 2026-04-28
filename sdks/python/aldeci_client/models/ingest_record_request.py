from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ingest_record_request_raw_record import IngestRecordRequestRawRecord


T = TypeVar("T", bound="IngestRecordRequest")


@_attrs_define
class IngestRecordRequest:
    """
    Attributes:
        org_id (str):
        source_name (str):
        raw_record (IngestRecordRequestRawRecord | Unset):
    """

    org_id: str
    source_name: str
    raw_record: IngestRecordRequestRawRecord | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        source_name = self.source_name

        raw_record: dict[str, Any] | Unset = UNSET
        if not isinstance(self.raw_record, Unset):
            raw_record = self.raw_record.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "source_name": source_name,
            }
        )
        if raw_record is not UNSET:
            field_dict["raw_record"] = raw_record

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ingest_record_request_raw_record import IngestRecordRequestRawRecord

        d = dict(src_dict)
        org_id = d.pop("org_id")

        source_name = d.pop("source_name")

        _raw_record = d.pop("raw_record", UNSET)
        raw_record: IngestRecordRequestRawRecord | Unset
        if isinstance(_raw_record, Unset):
            raw_record = UNSET
        else:
            raw_record = IngestRecordRequestRawRecord.from_dict(_raw_record)

        ingest_record_request = cls(
            org_id=org_id,
            source_name=source_name,
            raw_record=raw_record,
        )

        ingest_record_request.additional_properties = d
        return ingest_record_request

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
