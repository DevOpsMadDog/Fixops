from __future__ import annotations

from collections.abc import Mapping
from io import BytesIO
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import File

T = TypeVar("T", bound="BodyUploadChunkInputsStageChunksSessionIdPut")


@_attrs_define
class BodyUploadChunkInputsStageChunksSessionIdPut:
    """
    Attributes:
        chunk (File):
    """

    chunk: File
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        chunk = self.chunk.to_tuple()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "chunk": chunk,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        chunk = File(payload=BytesIO(d.pop("chunk")))

        body_upload_chunk_inputs_stage_chunks_session_id_put = cls(
            chunk=chunk,
        )

        body_upload_chunk_inputs_stage_chunks_session_id_put.additional_properties = d
        return body_upload_chunk_inputs_stage_chunks_session_id_put

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
