from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from .. import types
from ..types import UNSET, File, Unset

T = TypeVar("T", bound="BodyUploadScannerOutputApiV1ScannerIngestUploadPost")


@_attrs_define
class BodyUploadScannerOutputApiV1ScannerIngestUploadPost:
    """
    Attributes:
        file (File):
        scanner_type (None | str | Unset):
        app_id (str | Unset):  Default: ''.
        component (str | Unset):  Default: ''.
        pipeline (bool | Unset):  Default: False.
    """

    file: File
    scanner_type: None | str | Unset = UNSET
    app_id: str | Unset = ""
    component: str | Unset = ""
    pipeline: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file = self.file.to_tuple()

        scanner_type: None | str | Unset
        if isinstance(self.scanner_type, Unset):
            scanner_type = UNSET
        else:
            scanner_type = self.scanner_type

        app_id = self.app_id

        component = self.component

        pipeline = self.pipeline

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "file": file,
            }
        )
        if scanner_type is not UNSET:
            field_dict["scanner_type"] = scanner_type
        if app_id is not UNSET:
            field_dict["app_id"] = app_id
        if component is not UNSET:
            field_dict["component"] = component
        if pipeline is not UNSET:
            field_dict["pipeline"] = pipeline

        return field_dict

    def to_multipart(self) -> types.RequestFiles:
        files: types.RequestFiles = []

        files.append(("file", self.file.to_tuple()))

        if not isinstance(self.scanner_type, Unset):
            if isinstance(self.scanner_type, str):
                files.append(("scanner_type", (None, str(self.scanner_type).encode(), "text/plain")))
            else:
                files.append(("scanner_type", (None, str(self.scanner_type).encode(), "text/plain")))

        if not isinstance(self.app_id, Unset):
            files.append(("app_id", (None, str(self.app_id).encode(), "text/plain")))

        if not isinstance(self.component, Unset):
            files.append(("component", (None, str(self.component).encode(), "text/plain")))

        if not isinstance(self.pipeline, Unset):
            files.append(("pipeline", (None, str(self.pipeline).encode(), "text/plain")))

        for prop_name, prop in self.additional_properties.items():
            files.append((prop_name, (None, str(prop).encode(), "text/plain")))

        return files

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        file = File(payload=BytesIO(d.pop("file")))

        def _parse_scanner_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scanner_type = _parse_scanner_type(d.pop("scanner_type", UNSET))

        app_id = d.pop("app_id", UNSET)

        component = d.pop("component", UNSET)

        pipeline = d.pop("pipeline", UNSET)

        body_upload_scanner_output_api_v1_scanner_ingest_upload_post = cls(
            file=file,
            scanner_type=scanner_type,
            app_id=app_id,
            component=component,
            pipeline=pipeline,
        )

        body_upload_scanner_output_api_v1_scanner_ingest_upload_post.additional_properties = d
        return body_upload_scanner_output_api_v1_scanner_ingest_upload_post

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
