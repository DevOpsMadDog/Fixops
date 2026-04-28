from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.log_entry_store_metadata_type_0 import LogEntryStoreMetadataType0


T = TypeVar("T", bound="LogEntryStore")


@_attrs_define
class LogEntryStore:
    """
    Attributes:
        source_id (str):
        message (str):
        org_id (str | Unset):  Default: 'default'.
        level (str | Unset):  Default: 'info'.
        metadata (LogEntryStoreMetadataType0 | None | Unset):
    """

    source_id: str
    message: str
    org_id: str | Unset = "default"
    level: str | Unset = "info"
    metadata: LogEntryStoreMetadataType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.log_entry_store_metadata_type_0 import LogEntryStoreMetadataType0

        source_id = self.source_id

        message = self.message

        org_id = self.org_id

        level = self.level

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, LogEntryStoreMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_id": source_id,
                "message": message,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if level is not UNSET:
            field_dict["level"] = level
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.log_entry_store_metadata_type_0 import LogEntryStoreMetadataType0

        d = dict(src_dict)
        source_id = d.pop("source_id")

        message = d.pop("message")

        org_id = d.pop("org_id", UNSET)

        level = d.pop("level", UNSET)

        def _parse_metadata(data: object) -> LogEntryStoreMetadataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = LogEntryStoreMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(LogEntryStoreMetadataType0 | None | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        log_entry_store = cls(
            source_id=source_id,
            message=message,
            org_id=org_id,
            level=level,
            metadata=metadata,
        )

        log_entry_store.additional_properties = d
        return log_entry_store

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
