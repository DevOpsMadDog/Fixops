from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="FlowCheckRequest")


@_attrs_define
class FlowCheckRequest:
    """
    Attributes:
        src_segment_id (str):
        dst_segment_id (str):
        port (int):
    """

    src_segment_id: str
    dst_segment_id: str
    port: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        src_segment_id = self.src_segment_id

        dst_segment_id = self.dst_segment_id

        port = self.port

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "src_segment_id": src_segment_id,
                "dst_segment_id": dst_segment_id,
                "port": port,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        src_segment_id = d.pop("src_segment_id")

        dst_segment_id = d.pop("dst_segment_id")

        port = d.pop("port")

        flow_check_request = cls(
            src_segment_id=src_segment_id,
            dst_segment_id=dst_segment_id,
            port=port,
        )

        flow_check_request.additional_properties = d
        return flow_check_request

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
