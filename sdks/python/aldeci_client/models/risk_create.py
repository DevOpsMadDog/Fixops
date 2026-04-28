from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RiskCreate")


@_attrs_define
class RiskCreate:
    """
    Attributes:
        title (str):
        category (str | Unset): strategic|operational|compliance|financial|reputational Default: 'operational'.
        likelihood (int | Unset):  Default: 3.
        impact (int | Unset):  Default: 3.
        treatment (str | Unset): accept|mitigate|transfer|avoid Default: 'mitigate'.
        owner (str | Unset):  Default: ''.
        status (str | Unset): open|mitigated|accepted|closed Default: 'open'.
        notes (str | Unset):  Default: ''.
    """

    title: str
    category: str | Unset = "operational"
    likelihood: int | Unset = 3
    impact: int | Unset = 3
    treatment: str | Unset = "mitigate"
    owner: str | Unset = ""
    status: str | Unset = "open"
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        category = self.category

        likelihood = self.likelihood

        impact = self.impact

        treatment = self.treatment

        owner = self.owner

        status = self.status

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if category is not UNSET:
            field_dict["category"] = category
        if likelihood is not UNSET:
            field_dict["likelihood"] = likelihood
        if impact is not UNSET:
            field_dict["impact"] = impact
        if treatment is not UNSET:
            field_dict["treatment"] = treatment
        if owner is not UNSET:
            field_dict["owner"] = owner
        if status is not UNSET:
            field_dict["status"] = status
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        category = d.pop("category", UNSET)

        likelihood = d.pop("likelihood", UNSET)

        impact = d.pop("impact", UNSET)

        treatment = d.pop("treatment", UNSET)

        owner = d.pop("owner", UNSET)

        status = d.pop("status", UNSET)

        notes = d.pop("notes", UNSET)

        risk_create = cls(
            title=title,
            category=category,
            likelihood=likelihood,
            impact=impact,
            treatment=treatment,
            owner=owner,
            status=status,
            notes=notes,
        )

        risk_create.additional_properties = d
        return risk_create

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
