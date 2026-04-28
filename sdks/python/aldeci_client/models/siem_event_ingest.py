from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.siem_event_ingest_parsed_fields_type_0 import SIEMEventIngestParsedFieldsType0


T = TypeVar("T", bound="SIEMEventIngest")


@_attrs_define
class SIEMEventIngest:
    """
    Attributes:
        source_id (str):
        event_type (str):
        org_id (str | Unset):  Default: 'default'.
        severity (str | Unset):  Default: 'info'.
        raw_data (Any | Unset):
        parsed_fields (None | SIEMEventIngestParsedFieldsType0 | Unset):
    """

    source_id: str
    event_type: str
    org_id: str | Unset = "default"
    severity: str | Unset = "info"
    raw_data: Any | Unset = UNSET
    parsed_fields: None | SIEMEventIngestParsedFieldsType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.siem_event_ingest_parsed_fields_type_0 import SIEMEventIngestParsedFieldsType0

        source_id = self.source_id

        event_type = self.event_type

        org_id = self.org_id

        severity = self.severity

        raw_data = self.raw_data

        parsed_fields: dict[str, Any] | None | Unset
        if isinstance(self.parsed_fields, Unset):
            parsed_fields = UNSET
        elif isinstance(self.parsed_fields, SIEMEventIngestParsedFieldsType0):
            parsed_fields = self.parsed_fields.to_dict()
        else:
            parsed_fields = self.parsed_fields

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_id": source_id,
                "event_type": event_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if severity is not UNSET:
            field_dict["severity"] = severity
        if raw_data is not UNSET:
            field_dict["raw_data"] = raw_data
        if parsed_fields is not UNSET:
            field_dict["parsed_fields"] = parsed_fields

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.siem_event_ingest_parsed_fields_type_0 import SIEMEventIngestParsedFieldsType0

        d = dict(src_dict)
        source_id = d.pop("source_id")

        event_type = d.pop("event_type")

        org_id = d.pop("org_id", UNSET)

        severity = d.pop("severity", UNSET)

        raw_data = d.pop("raw_data", UNSET)

        def _parse_parsed_fields(data: object) -> None | SIEMEventIngestParsedFieldsType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                parsed_fields_type_0 = SIEMEventIngestParsedFieldsType0.from_dict(data)

                return parsed_fields_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SIEMEventIngestParsedFieldsType0 | Unset, data)

        parsed_fields = _parse_parsed_fields(d.pop("parsed_fields", UNSET))

        siem_event_ingest = cls(
            source_id=source_id,
            event_type=event_type,
            org_id=org_id,
            severity=severity,
            raw_data=raw_data,
            parsed_fields=parsed_fields,
        )

        siem_event_ingest.additional_properties = d
        return siem_event_ingest

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
