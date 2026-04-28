from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EvidenceCreate")


@_attrs_define
class EvidenceCreate:
    """
    Attributes:
        evidence_type (str | Unset):  Default: 'log_file'.
        filename (str | Unset):  Default: ''.
        size_bytes (int | Unset):  Default: 0.
        hash_md5 (str | Unset):  Default: ''.
        hash_sha256 (str | Unset):  Default: ''.
        storage_location (str | Unset):  Default: ''.
        notes (str | Unset):  Default: ''.
    """

    evidence_type: str | Unset = "log_file"
    filename: str | Unset = ""
    size_bytes: int | Unset = 0
    hash_md5: str | Unset = ""
    hash_sha256: str | Unset = ""
    storage_location: str | Unset = ""
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        evidence_type = self.evidence_type

        filename = self.filename

        size_bytes = self.size_bytes

        hash_md5 = self.hash_md5

        hash_sha256 = self.hash_sha256

        storage_location = self.storage_location

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if evidence_type is not UNSET:
            field_dict["evidence_type"] = evidence_type
        if filename is not UNSET:
            field_dict["filename"] = filename
        if size_bytes is not UNSET:
            field_dict["size_bytes"] = size_bytes
        if hash_md5 is not UNSET:
            field_dict["hash_md5"] = hash_md5
        if hash_sha256 is not UNSET:
            field_dict["hash_sha256"] = hash_sha256
        if storage_location is not UNSET:
            field_dict["storage_location"] = storage_location
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        evidence_type = d.pop("evidence_type", UNSET)

        filename = d.pop("filename", UNSET)

        size_bytes = d.pop("size_bytes", UNSET)

        hash_md5 = d.pop("hash_md5", UNSET)

        hash_sha256 = d.pop("hash_sha256", UNSET)

        storage_location = d.pop("storage_location", UNSET)

        notes = d.pop("notes", UNSET)

        evidence_create = cls(
            evidence_type=evidence_type,
            filename=filename,
            size_bytes=size_bytes,
            hash_md5=hash_md5,
            hash_sha256=hash_sha256,
            storage_location=storage_location,
            notes=notes,
        )

        evidence_create.additional_properties = d
        return evidence_create

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
