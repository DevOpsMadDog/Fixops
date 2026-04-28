from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import File

T = TypeVar("T", bound="BodyUploadBusinessContextApiV1BusinessContextUploadPost")


@_attrs_define
class BodyUploadBusinessContextApiV1BusinessContextUploadPost:
    """
    Attributes:
        file (File):
        service_name (str):
        format_type (str):
    """

    file: File
    service_name: str
    format_type: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file = self.file.to_tuple()

        service_name = self.service_name

        format_type = self.format_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "file": file,
                "service_name": service_name,
                "format_type": format_type,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        file = File(payload=BytesIO(d.pop("file")))

        service_name = d.pop("service_name")

        format_type = d.pop("format_type")

        body_upload_business_context_api_v1_business_context_upload_post = cls(
            file=file,
            service_name=service_name,
            format_type=format_type,
        )

        body_upload_business_context_api_v1_business_context_upload_post.additional_properties = d
        return body_upload_business_context_api_v1_business_context_upload_post

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
