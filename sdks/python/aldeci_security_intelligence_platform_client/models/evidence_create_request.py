from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.evidence_type import EvidenceType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.evidence_create_request_metadata import EvidenceCreateRequestMetadata


T = TypeVar("T", bound="EvidenceCreateRequest")


@_attrs_define
class EvidenceCreateRequest:
    """
    Attributes:
        control_id (str):
        framework (str):
        type_ (EvidenceType):
        title (str):
        description (str):
        collected_by (str):
        file_hash (None | str | Unset):
        file_size (int | None | Unset):
        metadata (EvidenceCreateRequestMetadata | Unset):
    """

    control_id: str
    framework: str
    type_: EvidenceType
    title: str
    description: str
    collected_by: str
    file_hash: None | str | Unset = UNSET
    file_size: int | None | Unset = UNSET
    metadata: EvidenceCreateRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_id = self.control_id

        framework = self.framework

        type_ = self.type_.value

        title = self.title

        description = self.description

        collected_by = self.collected_by

        file_hash: None | str | Unset
        if isinstance(self.file_hash, Unset):
            file_hash = UNSET
        else:
            file_hash = self.file_hash

        file_size: int | None | Unset
        if isinstance(self.file_size, Unset):
            file_size = UNSET
        else:
            file_size = self.file_size

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_id": control_id,
                "framework": framework,
                "type": type_,
                "title": title,
                "description": description,
                "collected_by": collected_by,
            }
        )
        if file_hash is not UNSET:
            field_dict["file_hash"] = file_hash
        if file_size is not UNSET:
            field_dict["file_size"] = file_size
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.evidence_create_request_metadata import EvidenceCreateRequestMetadata

        d = dict(src_dict)
        control_id = d.pop("control_id")

        framework = d.pop("framework")

        type_ = EvidenceType(d.pop("type"))

        title = d.pop("title")

        description = d.pop("description")

        collected_by = d.pop("collected_by")

        def _parse_file_hash(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        file_hash = _parse_file_hash(d.pop("file_hash", UNSET))

        def _parse_file_size(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        file_size = _parse_file_size(d.pop("file_size", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: EvidenceCreateRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = EvidenceCreateRequestMetadata.from_dict(_metadata)

        evidence_create_request = cls(
            control_id=control_id,
            framework=framework,
            type_=type_,
            title=title,
            description=description,
            collected_by=collected_by,
            file_hash=file_hash,
            file_size=file_size,
            metadata=metadata,
        )

        evidence_create_request.additional_properties = d
        return evidence_create_request

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
