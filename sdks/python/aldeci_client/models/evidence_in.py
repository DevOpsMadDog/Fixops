from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EvidenceIn")


@_attrs_define
class EvidenceIn:
    """
    Attributes:
        evidence_type (str | Unset):  Default: 'file'.
        filename (str | Unset):  Default: ''.
        hash_md5 (str | Unset):  Default: ''.
        hash_sha256 (str | Unset):  Default: ''.
        size_bytes (int | Unset):  Default: 0.
        collected_by (str | Unset):  Default: ''.
        collection_method (str | Unset):  Default: ''.
        storage_location (str | Unset):  Default: ''.
    """

    evidence_type: str | Unset = "file"
    filename: str | Unset = ""
    hash_md5: str | Unset = ""
    hash_sha256: str | Unset = ""
    size_bytes: int | Unset = 0
    collected_by: str | Unset = ""
    collection_method: str | Unset = ""
    storage_location: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        evidence_type = self.evidence_type

        filename = self.filename

        hash_md5 = self.hash_md5

        hash_sha256 = self.hash_sha256

        size_bytes = self.size_bytes

        collected_by = self.collected_by

        collection_method = self.collection_method

        storage_location = self.storage_location

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if evidence_type is not UNSET:
            field_dict["evidence_type"] = evidence_type
        if filename is not UNSET:
            field_dict["filename"] = filename
        if hash_md5 is not UNSET:
            field_dict["hash_md5"] = hash_md5
        if hash_sha256 is not UNSET:
            field_dict["hash_sha256"] = hash_sha256
        if size_bytes is not UNSET:
            field_dict["size_bytes"] = size_bytes
        if collected_by is not UNSET:
            field_dict["collected_by"] = collected_by
        if collection_method is not UNSET:
            field_dict["collection_method"] = collection_method
        if storage_location is not UNSET:
            field_dict["storage_location"] = storage_location

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        evidence_type = d.pop("evidence_type", UNSET)

        filename = d.pop("filename", UNSET)

        hash_md5 = d.pop("hash_md5", UNSET)

        hash_sha256 = d.pop("hash_sha256", UNSET)

        size_bytes = d.pop("size_bytes", UNSET)

        collected_by = d.pop("collected_by", UNSET)

        collection_method = d.pop("collection_method", UNSET)

        storage_location = d.pop("storage_location", UNSET)

        evidence_in = cls(
            evidence_type=evidence_type,
            filename=filename,
            hash_md5=hash_md5,
            hash_sha256=hash_sha256,
            size_bytes=size_bytes,
            collected_by=collected_by,
            collection_method=collection_method,
            storage_location=storage_location,
        )

        evidence_in.additional_properties = d
        return evidence_in

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
