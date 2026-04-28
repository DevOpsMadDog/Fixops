from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import File

T = TypeVar("T", bound="BodyIngestRawApiV1ConnectorsIngestRawPost")


@_attrs_define
class BodyIngestRawApiV1ConnectorsIngestRawPost:
    """
    Attributes:
        file (File):
        scan_type (str):
        product_name (str):
    """

    file: File
    scan_type: str
    product_name: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file = self.file.to_tuple()

        scan_type = self.scan_type

        product_name = self.product_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "file": file,
                "scan_type": scan_type,
                "product_name": product_name,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        file = File(payload=BytesIO(d.pop("file")))

        scan_type = d.pop("scan_type")

        product_name = d.pop("product_name")

        body_ingest_raw_api_v1_connectors_ingest_raw_post = cls(
            file=file,
            scan_type=scan_type,
            product_name=product_name,
        )

        body_ingest_raw_api_v1_connectors_ingest_raw_post.additional_properties = d
        return body_ingest_raw_api_v1_connectors_ingest_raw_post

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
