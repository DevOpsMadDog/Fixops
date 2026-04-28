from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GraphQueryRequest")


@_attrs_define
class GraphQueryRequest:
    """
    Attributes:
        org_id (str):
        query_text (str):
        target_cores (list[int] | Unset):
        max_results (int | Unset):  Default: 20.
        include_relationships (bool | Unset):  Default: True.
        confidence_threshold (float | Unset):  Default: 0.5.
    """

    org_id: str
    query_text: str
    target_cores: list[int] | Unset = UNSET
    max_results: int | Unset = 20
    include_relationships: bool | Unset = True
    confidence_threshold: float | Unset = 0.5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        query_text = self.query_text

        target_cores: list[int] | Unset = UNSET
        if not isinstance(self.target_cores, Unset):
            target_cores = self.target_cores

        max_results = self.max_results

        include_relationships = self.include_relationships

        confidence_threshold = self.confidence_threshold

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "query_text": query_text,
            }
        )
        if target_cores is not UNSET:
            field_dict["target_cores"] = target_cores
        if max_results is not UNSET:
            field_dict["max_results"] = max_results
        if include_relationships is not UNSET:
            field_dict["include_relationships"] = include_relationships
        if confidence_threshold is not UNSET:
            field_dict["confidence_threshold"] = confidence_threshold

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        query_text = d.pop("query_text")

        target_cores = cast(list[int], d.pop("target_cores", UNSET))

        max_results = d.pop("max_results", UNSET)

        include_relationships = d.pop("include_relationships", UNSET)

        confidence_threshold = d.pop("confidence_threshold", UNSET)

        graph_query_request = cls(
            org_id=org_id,
            query_text=query_text,
            target_cores=target_cores,
            max_results=max_results,
            include_relationships=include_relationships,
            confidence_threshold=confidence_threshold,
        )

        graph_query_request.additional_properties = d
        return graph_query_request

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
