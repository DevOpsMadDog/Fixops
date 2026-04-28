from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LinkChainsRequest")


@_attrs_define
class LinkChainsRequest:
    """
    Attributes:
        source_chain_id (str): Source attack chain ID
        target_chain_id (str): Target attack chain ID
        org_id (str | Unset):  Default: 'default'.
        link_type (str | Unset): lateral_movement/persistence/escalation Default: 'lateral_movement'.
        confidence (float | Unset):  Default: 50.0.
    """

    source_chain_id: str
    target_chain_id: str
    org_id: str | Unset = "default"
    link_type: str | Unset = "lateral_movement"
    confidence: float | Unset = 50.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_chain_id = self.source_chain_id

        target_chain_id = self.target_chain_id

        org_id = self.org_id

        link_type = self.link_type

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_chain_id": source_chain_id,
                "target_chain_id": target_chain_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if link_type is not UNSET:
            field_dict["link_type"] = link_type
        if confidence is not UNSET:
            field_dict["confidence"] = confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_chain_id = d.pop("source_chain_id")

        target_chain_id = d.pop("target_chain_id")

        org_id = d.pop("org_id", UNSET)

        link_type = d.pop("link_type", UNSET)

        confidence = d.pop("confidence", UNSET)

        link_chains_request = cls(
            source_chain_id=source_chain_id,
            target_chain_id=target_chain_id,
            org_id=org_id,
            link_type=link_type,
            confidence=confidence,
        )

        link_chains_request.additional_properties = d
        return link_chains_request

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
