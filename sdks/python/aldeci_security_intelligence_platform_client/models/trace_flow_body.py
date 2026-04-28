from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TraceFlowBody")


@_attrs_define
class TraceFlowBody:
    """
    Attributes:
        start_ref (str): Starting node ref (service id or name)
        max_hops (int | Unset):  Default: 5.
    """

    start_ref: str
    max_hops: int | Unset = 5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        start_ref = self.start_ref

        max_hops = self.max_hops

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "start_ref": start_ref,
            }
        )
        if max_hops is not UNSET:
            field_dict["max_hops"] = max_hops

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        start_ref = d.pop("start_ref")

        max_hops = d.pop("max_hops", UNSET)

        trace_flow_body = cls(
            start_ref=start_ref,
            max_hops=max_hops,
        )

        trace_flow_body.additional_properties = d
        return trace_flow_body

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
