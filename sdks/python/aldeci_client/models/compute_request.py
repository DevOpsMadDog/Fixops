from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ComputeRequest")


@_attrs_define
class ComputeRequest:
    """
    Attributes:
        source_ids (list[str]): Source (entry) node IDs — virtual super-source is linked to these.
        sink_ids (list[str]): Sink (crown jewel) node IDs — virtual super-sink is linked from these.
        org_id (str | Unset): Organisation ID Default: 'default'.
        top_k (int | Unset): Maximum choke edges to return Default: 10.
    """

    source_ids: list[str]
    sink_ids: list[str]
    org_id: str | Unset = "default"
    top_k: int | Unset = 10
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_ids = self.source_ids

        sink_ids = self.sink_ids

        org_id = self.org_id

        top_k = self.top_k

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_ids": source_ids,
                "sink_ids": sink_ids,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if top_k is not UNSET:
            field_dict["top_k"] = top_k

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_ids = cast(list[str], d.pop("source_ids"))

        sink_ids = cast(list[str], d.pop("sink_ids"))

        org_id = d.pop("org_id", UNSET)

        top_k = d.pop("top_k", UNSET)

        compute_request = cls(
            source_ids=source_ids,
            sink_ids=sink_ids,
            org_id=org_id,
            top_k=top_k,
        )

        compute_request.additional_properties = d
        return compute_request

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
