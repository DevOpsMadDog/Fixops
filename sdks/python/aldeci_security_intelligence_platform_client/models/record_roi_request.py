from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordROIRequest")


@_attrs_define
class RecordROIRequest:
    """
    Attributes:
        initiative_name (str): Name of the security initiative
        investment_amount (float): Total investment amount
        estimated_risk_reduction (float): Estimated risk reduction % (0-100)
        category (str | Unset): Budget category Default: ''.
        assessment_date (None | str | Unset): ISO assessment date
        notes (str | Unset): Optional notes Default: ''.
    """

    initiative_name: str
    investment_amount: float
    estimated_risk_reduction: float
    category: str | Unset = ""
    assessment_date: None | str | Unset = UNSET
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        initiative_name = self.initiative_name

        investment_amount = self.investment_amount

        estimated_risk_reduction = self.estimated_risk_reduction

        category = self.category

        assessment_date: None | str | Unset
        if isinstance(self.assessment_date, Unset):
            assessment_date = UNSET
        else:
            assessment_date = self.assessment_date

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "initiative_name": initiative_name,
                "investment_amount": investment_amount,
                "estimated_risk_reduction": estimated_risk_reduction,
            }
        )
        if category is not UNSET:
            field_dict["category"] = category
        if assessment_date is not UNSET:
            field_dict["assessment_date"] = assessment_date
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        initiative_name = d.pop("initiative_name")

        investment_amount = d.pop("investment_amount")

        estimated_risk_reduction = d.pop("estimated_risk_reduction")

        category = d.pop("category", UNSET)

        def _parse_assessment_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assessment_date = _parse_assessment_date(d.pop("assessment_date", UNSET))

        notes = d.pop("notes", UNSET)

        record_roi_request = cls(
            initiative_name=initiative_name,
            investment_amount=investment_amount,
            estimated_risk_reduction=estimated_risk_reduction,
            category=category,
            assessment_date=assessment_date,
            notes=notes,
        )

        record_roi_request.additional_properties = d
        return record_roi_request

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
