from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, File, FileTypes, Unset

T = TypeVar("T", bound="BodyFingerprintBlobApiV1BinaryFpFingerprintPost")


@_attrs_define
class BodyFingerprintBlobApiV1BinaryFpFingerprintPost:
    """
    Attributes:
        file (File | None | Unset):
        blob_base64 (None | str | Unset):
    """

    file: File | None | Unset = UNSET
    blob_base64: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file: FileTypes | None | Unset
        if isinstance(self.file, Unset):
            file = UNSET
        elif isinstance(self.file, File):
            file = self.file.to_tuple()

        else:
            file = self.file

        blob_base64: None | str | Unset
        if isinstance(self.blob_base64, Unset):
            blob_base64 = UNSET
        else:
            blob_base64 = self.blob_base64

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if file is not UNSET:
            field_dict["file"] = file
        if blob_base64 is not UNSET:
            field_dict["blob_base64"] = blob_base64

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_file(data: object) -> File | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, bytes):
                    raise TypeError()
                file_type_0 = File(payload=BytesIO(data))

                return file_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(File | None | Unset, data)

        file = _parse_file(d.pop("file", UNSET))

        def _parse_blob_base64(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        blob_base64 = _parse_blob_base64(d.pop("blob_base64", UNSET))

        body_fingerprint_blob_api_v1_binary_fp_fingerprint_post = cls(
            file=file,
            blob_base64=blob_base64,
        )

        body_fingerprint_blob_api_v1_binary_fp_fingerprint_post.additional_properties = d
        return body_fingerprint_blob_api_v1_binary_fp_fingerprint_post

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
