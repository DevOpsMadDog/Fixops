from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddSectionRequest")


@_attrs_define
class AddSectionRequest:
    """
    Attributes:
        section_name (str): Section name
        org_id (str | Unset): Organisation ID Default: 'default'.
        section_type (str | Unset): summary/risk/compliance/incidents/vulnerabilities/recommendations/kpis Default:
            'summary'.
        content (str | Unset): Section content / narrative Default: ''.
        score (float | Unset): Section score 0-100 Default: 0.0.
        sort_order (int | Unset): Display order Default: 0.
    """

    section_name: str
    org_id: str | Unset = "default"
    section_type: str | Unset = "summary"
    content: str | Unset = ""
    score: float | Unset = 0.0
    sort_order: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        section_name = self.section_name

        org_id = self.org_id

        section_type = self.section_type

        content = self.content

        score = self.score

        sort_order = self.sort_order

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "section_name": section_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if section_type is not UNSET:
            field_dict["section_type"] = section_type
        if content is not UNSET:
            field_dict["content"] = content
        if score is not UNSET:
            field_dict["score"] = score
        if sort_order is not UNSET:
            field_dict["sort_order"] = sort_order

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        section_name = d.pop("section_name")

        org_id = d.pop("org_id", UNSET)

        section_type = d.pop("section_type", UNSET)

        content = d.pop("content", UNSET)

        score = d.pop("score", UNSET)

        sort_order = d.pop("sort_order", UNSET)

        add_section_request = cls(
            section_name=section_name,
            org_id=org_id,
            section_type=section_type,
            content=content,
            score=score,
            sort_order=sort_order,
        )

        add_section_request.additional_properties = d
        return add_section_request

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
