from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="QuerySimilarBody")


@_attrs_define
class QuerySimilarBody:
    """
    Attributes:
        org_id (str): Organisation ID
        blob_base64 (str): Base64-encoded binary blob
        min_similarity (float | Unset):  Default: 0.85.
    """

    org_id: str
    blob_base64: str
    min_similarity: float | Unset = 0.85
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        blob_base64 = self.blob_base64

        min_similarity = self.min_similarity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "blob_base64": blob_base64,
            }
        )
        if min_similarity is not UNSET:
            field_dict["min_similarity"] = min_similarity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        blob_base64 = d.pop("blob_base64")

        min_similarity = d.pop("min_similarity", UNSET)

        query_similar_body = cls(
            org_id=org_id,
            blob_base64=blob_base64,
            min_similarity=min_similarity,
        )

        query_similar_body.additional_properties = d
        return query_similar_body

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
