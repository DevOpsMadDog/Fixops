from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.risk_category import RiskCategory
from ..types import UNSET, Unset

T = TypeVar("T", bound="SetAppetiteRequest")


@_attrs_define
class SetAppetiteRequest:
    """
    Attributes:
        category (RiskCategory):
        appetite_score (float): Maximum acceptable residual risk score
        tolerance_score (float): Escalation threshold
        description (str | Unset):  Default: ''.
        updated_by (str | Unset):  Default: ''.
        org_id (str | Unset):  Default: 'default'.
    """

    category: RiskCategory
    appetite_score: float
    tolerance_score: float
    description: str | Unset = ""
    updated_by: str | Unset = ""
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        category = self.category.value

        appetite_score = self.appetite_score

        tolerance_score = self.tolerance_score

        description = self.description

        updated_by = self.updated_by

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "category": category,
                "appetite_score": appetite_score,
                "tolerance_score": tolerance_score,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if updated_by is not UNSET:
            field_dict["updated_by"] = updated_by
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        category = RiskCategory(d.pop("category"))

        appetite_score = d.pop("appetite_score")

        tolerance_score = d.pop("tolerance_score")

        description = d.pop("description", UNSET)

        updated_by = d.pop("updated_by", UNSET)

        org_id = d.pop("org_id", UNSET)

        set_appetite_request = cls(
            category=category,
            appetite_score=appetite_score,
            tolerance_score=tolerance_score,
            description=description,
            updated_by=updated_by,
            org_id=org_id,
        )

        set_appetite_request.additional_properties = d
        return set_appetite_request

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
