from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="QueryRequest")


@_attrs_define
class QueryRequest:
    """
    Attributes:
        start_fqn (str):
        target_fqn (str):
        org_id (str | Unset):  Default: 'default'.
        max_depth (int | Unset):  Default: 10.
    """

    start_fqn: str
    target_fqn: str
    org_id: str | Unset = "default"
    max_depth: int | Unset = 10
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        start_fqn = self.start_fqn

        target_fqn = self.target_fqn

        org_id = self.org_id

        max_depth = self.max_depth

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "start_fqn": start_fqn,
                "target_fqn": target_fqn,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if max_depth is not UNSET:
            field_dict["max_depth"] = max_depth

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        start_fqn = d.pop("start_fqn")

        target_fqn = d.pop("target_fqn")

        org_id = d.pop("org_id", UNSET)

        max_depth = d.pop("max_depth", UNSET)

        query_request = cls(
            start_fqn=start_fqn,
            target_fqn=target_fqn,
            org_id=org_id,
            max_depth=max_depth,
        )

        query_request.additional_properties = d
        return query_request

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
