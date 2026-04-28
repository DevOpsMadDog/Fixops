from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EvidenceAdd")


@_attrs_define
class EvidenceAdd:
    """
    Attributes:
        org_id (str):
        evidence_type (str | Unset):  Default: 'log'.
        content (str | Unset):  Default: ''.
    """

    org_id: str
    evidence_type: str | Unset = "log"
    content: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        evidence_type = self.evidence_type

        content = self.content

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if evidence_type is not UNSET:
            field_dict["evidence_type"] = evidence_type
        if content is not UNSET:
            field_dict["content"] = content

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        evidence_type = d.pop("evidence_type", UNSET)

        content = d.pop("content", UNSET)

        evidence_add = cls(
            org_id=org_id,
            evidence_type=evidence_type,
            content=content,
        )

        evidence_add.additional_properties = d
        return evidence_add

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
