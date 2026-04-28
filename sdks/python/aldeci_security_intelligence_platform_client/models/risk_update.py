from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RiskUpdate")


@_attrs_define
class RiskUpdate:
    """
    Attributes:
        title (None | str | Unset):
        category (None | str | Unset):
        likelihood (int | None | Unset):
        impact (int | None | Unset):
        treatment (None | str | Unset):
        owner (None | str | Unset):
        status (None | str | Unset):
        notes (None | str | Unset):
    """

    title: None | str | Unset = UNSET
    category: None | str | Unset = UNSET
    likelihood: int | None | Unset = UNSET
    impact: int | None | Unset = UNSET
    treatment: None | str | Unset = UNSET
    owner: None | str | Unset = UNSET
    status: None | str | Unset = UNSET
    notes: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title: None | str | Unset
        if isinstance(self.title, Unset):
            title = UNSET
        else:
            title = self.title

        category: None | str | Unset
        if isinstance(self.category, Unset):
            category = UNSET
        else:
            category = self.category

        likelihood: int | None | Unset
        if isinstance(self.likelihood, Unset):
            likelihood = UNSET
        else:
            likelihood = self.likelihood

        impact: int | None | Unset
        if isinstance(self.impact, Unset):
            impact = UNSET
        else:
            impact = self.impact

        treatment: None | str | Unset
        if isinstance(self.treatment, Unset):
            treatment = UNSET
        else:
            treatment = self.treatment

        owner: None | str | Unset
        if isinstance(self.owner, Unset):
            owner = UNSET
        else:
            owner = self.owner

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if title is not UNSET:
            field_dict["title"] = title
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

        def _parse_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        title = _parse_title(d.pop("title", UNSET))

        def _parse_category(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        category = _parse_category(d.pop("category", UNSET))

        def _parse_likelihood(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        likelihood = _parse_likelihood(d.pop("likelihood", UNSET))

        def _parse_impact(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        impact = _parse_impact(d.pop("impact", UNSET))

        def _parse_treatment(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        treatment = _parse_treatment(d.pop("treatment", UNSET))

        def _parse_owner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner = _parse_owner(d.pop("owner", UNSET))

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        risk_update = cls(
            title=title,
            category=category,
            likelihood=likelihood,
            impact=impact,
            treatment=treatment,
            owner=owner,
            status=status,
            notes=notes,
        )

        risk_update.additional_properties = d
        return risk_update

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
