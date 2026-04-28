from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddAliasRequest")


@_attrs_define
class AddAliasRequest:
    """
    Attributes:
        canonical_id (str):
        alias_name (str):
        source (str | Unset):  Default: 'manual'.
        confidence (float | Unset):  Default: 1.0.
    """

    canonical_id: str
    alias_name: str
    source: str | Unset = "manual"
    confidence: float | Unset = 1.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        canonical_id = self.canonical_id

        alias_name = self.alias_name

        source = self.source

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "canonical_id": canonical_id,
                "alias_name": alias_name,
            }
        )
        if source is not UNSET:
            field_dict["source"] = source
        if confidence is not UNSET:
            field_dict["confidence"] = confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        canonical_id = d.pop("canonical_id")

        alias_name = d.pop("alias_name")

        source = d.pop("source", UNSET)

        confidence = d.pop("confidence", UNSET)

        add_alias_request = cls(
            canonical_id=canonical_id,
            alias_name=alias_name,
            source=source,
            confidence=confidence,
        )

        add_alias_request.additional_properties = d
        return add_alias_request

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
