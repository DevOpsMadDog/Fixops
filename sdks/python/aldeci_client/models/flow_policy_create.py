from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FlowPolicyCreate")


@_attrs_define
class FlowPolicyCreate:
    """
    Attributes:
        src_segment_id (str):
        dst_segment_id (str):
        action (str):
        ports (list[str] | Unset):
        justification (str | Unset):  Default: ''.
    """

    src_segment_id: str
    dst_segment_id: str
    action: str
    ports: list[str] | Unset = UNSET
    justification: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        src_segment_id = self.src_segment_id

        dst_segment_id = self.dst_segment_id

        action = self.action

        ports: list[str] | Unset = UNSET
        if not isinstance(self.ports, Unset):
            ports = self.ports

        justification = self.justification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "src_segment_id": src_segment_id,
                "dst_segment_id": dst_segment_id,
                "action": action,
            }
        )
        if ports is not UNSET:
            field_dict["ports"] = ports
        if justification is not UNSET:
            field_dict["justification"] = justification

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        src_segment_id = d.pop("src_segment_id")

        dst_segment_id = d.pop("dst_segment_id")

        action = d.pop("action")

        ports = cast(list[str], d.pop("ports", UNSET))

        justification = d.pop("justification", UNSET)

        flow_policy_create = cls(
            src_segment_id=src_segment_id,
            dst_segment_id=dst_segment_id,
            action=action,
            ports=ports,
            justification=justification,
        )

        flow_policy_create.additional_properties = d
        return flow_policy_create

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
