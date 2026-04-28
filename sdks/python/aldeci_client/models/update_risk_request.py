from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.risk_category import RiskCategory
from ..models.risk_status import RiskStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateRiskRequest")


@_attrs_define
class UpdateRiskRequest:
    """
    Attributes:
        title (None | str | Unset):
        description (None | str | Unset):
        category (None | RiskCategory | Unset):
        owner (None | str | Unset):
        likelihood (int | None | Unset):
        impact (int | None | Unset):
        status (None | RiskStatus | Unset):
        tags (list[str] | None | Unset):
        related_finding_ids (list[str] | None | Unset):
    """

    title: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    category: None | RiskCategory | Unset = UNSET
    owner: None | str | Unset = UNSET
    likelihood: int | None | Unset = UNSET
    impact: int | None | Unset = UNSET
    status: None | RiskStatus | Unset = UNSET
    tags: list[str] | None | Unset = UNSET
    related_finding_ids: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title: None | str | Unset
        if isinstance(self.title, Unset):
            title = UNSET
        else:
            title = self.title

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        category: None | str | Unset
        if isinstance(self.category, Unset):
            category = UNSET
        elif isinstance(self.category, RiskCategory):
            category = self.category.value
        else:
            category = self.category

        owner: None | str | Unset
        if isinstance(self.owner, Unset):
            owner = UNSET
        else:
            owner = self.owner

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

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        elif isinstance(self.status, RiskStatus):
            status = self.status.value
        else:
            status = self.status

        tags: list[str] | None | Unset
        if isinstance(self.tags, Unset):
            tags = UNSET
        elif isinstance(self.tags, list):
            tags = self.tags

        else:
            tags = self.tags

        related_finding_ids: list[str] | None | Unset
        if isinstance(self.related_finding_ids, Unset):
            related_finding_ids = UNSET
        elif isinstance(self.related_finding_ids, list):
            related_finding_ids = self.related_finding_ids

        else:
            related_finding_ids = self.related_finding_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if title is not UNSET:
            field_dict["title"] = title
        if description is not UNSET:
            field_dict["description"] = description
        if category is not UNSET:
            field_dict["category"] = category
        if owner is not UNSET:
            field_dict["owner"] = owner
        if likelihood is not UNSET:
            field_dict["likelihood"] = likelihood
        if impact is not UNSET:
            field_dict["impact"] = impact
        if status is not UNSET:
            field_dict["status"] = status
        if tags is not UNSET:
            field_dict["tags"] = tags
        if related_finding_ids is not UNSET:
            field_dict["related_finding_ids"] = related_finding_ids

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

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_category(data: object) -> None | RiskCategory | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                category_type_0 = RiskCategory(data)

                return category_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RiskCategory | Unset, data)

        category = _parse_category(d.pop("category", UNSET))

        def _parse_owner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner = _parse_owner(d.pop("owner", UNSET))

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

        def _parse_status(data: object) -> None | RiskStatus | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                status_type_0 = RiskStatus(data)

                return status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RiskStatus | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_tags(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                tags_type_0 = cast(list[str], data)

                return tags_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        tags = _parse_tags(d.pop("tags", UNSET))

        def _parse_related_finding_ids(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                related_finding_ids_type_0 = cast(list[str], data)

                return related_finding_ids_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        related_finding_ids = _parse_related_finding_ids(d.pop("related_finding_ids", UNSET))

        update_risk_request = cls(
            title=title,
            description=description,
            category=category,
            owner=owner,
            likelihood=likelihood,
            impact=impact,
            status=status,
            tags=tags,
            related_finding_ids=related_finding_ids,
        )

        update_risk_request.additional_properties = d
        return update_risk_request

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
