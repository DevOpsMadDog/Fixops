from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ingest_request_metadata import IngestRequestMetadata


T = TypeVar("T", bound="IngestRequest")


@_attrs_define
class IngestRequest:
    """
    Attributes:
        data_id (str): Unique data identifier
        category (str): Data category: evidence, findings, scans, etc.
        content (str): Data content (string or JSON)
        metadata (IngestRequestMetadata | Unset):
    """

    data_id: str
    category: str
    content: str
    metadata: IngestRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data_id = self.data_id

        category = self.category

        content = self.content

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "data_id": data_id,
                "category": category,
                "content": content,
            }
        )
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ingest_request_metadata import IngestRequestMetadata

        d = dict(src_dict)
        data_id = d.pop("data_id")

        category = d.pop("category")

        content = d.pop("content")

        _metadata = d.pop("metadata", UNSET)
        metadata: IngestRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = IngestRequestMetadata.from_dict(_metadata)

        ingest_request = cls(
            data_id=data_id,
            category=category,
            content=content,
            metadata=metadata,
        )

        ingest_request.additional_properties = d
        return ingest_request

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
