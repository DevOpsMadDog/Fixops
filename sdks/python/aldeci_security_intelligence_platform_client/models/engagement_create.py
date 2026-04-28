from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EngagementCreate")


@_attrs_define
class EngagementCreate:
    """
    Attributes:
        name (str):
        engagement_type (str | Unset):  Default: 'internal'.
        methodology (str | Unset):  Default: 'PTES'.
        scope_description (str | Unset):  Default: ''.
        start_date (str | Unset):  Default: ''.
        end_date (str | Unset):  Default: ''.
        lead_operator (str | Unset):  Default: ''.
        classification (str | Unset):  Default: 'confidential'.
    """

    name: str
    engagement_type: str | Unset = "internal"
    methodology: str | Unset = "PTES"
    scope_description: str | Unset = ""
    start_date: str | Unset = ""
    end_date: str | Unset = ""
    lead_operator: str | Unset = ""
    classification: str | Unset = "confidential"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        engagement_type = self.engagement_type

        methodology = self.methodology

        scope_description = self.scope_description

        start_date = self.start_date

        end_date = self.end_date

        lead_operator = self.lead_operator

        classification = self.classification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if engagement_type is not UNSET:
            field_dict["engagement_type"] = engagement_type
        if methodology is not UNSET:
            field_dict["methodology"] = methodology
        if scope_description is not UNSET:
            field_dict["scope_description"] = scope_description
        if start_date is not UNSET:
            field_dict["start_date"] = start_date
        if end_date is not UNSET:
            field_dict["end_date"] = end_date
        if lead_operator is not UNSET:
            field_dict["lead_operator"] = lead_operator
        if classification is not UNSET:
            field_dict["classification"] = classification

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        engagement_type = d.pop("engagement_type", UNSET)

        methodology = d.pop("methodology", UNSET)

        scope_description = d.pop("scope_description", UNSET)

        start_date = d.pop("start_date", UNSET)

        end_date = d.pop("end_date", UNSET)

        lead_operator = d.pop("lead_operator", UNSET)

        classification = d.pop("classification", UNSET)

        engagement_create = cls(
            name=name,
            engagement_type=engagement_type,
            methodology=methodology,
            scope_description=scope_description,
            start_date=start_date,
            end_date=end_date,
            lead_operator=lead_operator,
            classification=classification,
        )

        engagement_create.additional_properties = d
        return engagement_create

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
