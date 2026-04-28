from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.risk_category import RiskCategory
from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateRiskRequest")


@_attrs_define
class CreateRiskRequest:
    """
    Attributes:
        title (str): Short descriptive title
        category (RiskCategory):
        description (str | Unset): Detailed description Default: ''.
        owner (str | Unset): Risk owner (name or email) Default: ''.
        likelihood (int | Unset): Likelihood 1-5 Default: 3.
        impact (int | Unset): Impact 1-5 Default: 3.
        tags (list[str] | Unset):
        related_finding_ids (list[str] | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    title: str
    category: RiskCategory
    description: str | Unset = ""
    owner: str | Unset = ""
    likelihood: int | Unset = 3
    impact: int | Unset = 3
    tags: list[str] | Unset = UNSET
    related_finding_ids: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        category = self.category.value

        description = self.description

        owner = self.owner

        likelihood = self.likelihood

        impact = self.impact

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        related_finding_ids: list[str] | Unset = UNSET
        if not isinstance(self.related_finding_ids, Unset):
            related_finding_ids = self.related_finding_ids

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "category": category,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if owner is not UNSET:
            field_dict["owner"] = owner
        if likelihood is not UNSET:
            field_dict["likelihood"] = likelihood
        if impact is not UNSET:
            field_dict["impact"] = impact
        if tags is not UNSET:
            field_dict["tags"] = tags
        if related_finding_ids is not UNSET:
            field_dict["related_finding_ids"] = related_finding_ids
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        category = RiskCategory(d.pop("category"))

        description = d.pop("description", UNSET)

        owner = d.pop("owner", UNSET)

        likelihood = d.pop("likelihood", UNSET)

        impact = d.pop("impact", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        related_finding_ids = cast(list[str], d.pop("related_finding_ids", UNSET))

        org_id = d.pop("org_id", UNSET)

        create_risk_request = cls(
            title=title,
            category=category,
            description=description,
            owner=owner,
            likelihood=likelihood,
            impact=impact,
            tags=tags,
            related_finding_ids=related_finding_ids,
            org_id=org_id,
        )

        create_risk_request.additional_properties = d
        return create_risk_request

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
