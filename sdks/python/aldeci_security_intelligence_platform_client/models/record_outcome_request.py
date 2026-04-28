from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordOutcomeRequest")


@_attrs_define
class RecordOutcomeRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        outcome_type (str): cost-avoidance|incident-reduction|efficiency|compliance|risk-reduction|revenue-protection
        description (str | Unset): Outcome description Default: ''.
        quantified_value (float | Unset): Quantified monetary value Default: 0.0.
        measurement_date (str | Unset): ISO measurement date Default: ''.
        verified (bool | Unset): Whether outcome is verified Default: False.
    """

    org_id: str
    outcome_type: str
    description: str | Unset = ""
    quantified_value: float | Unset = 0.0
    measurement_date: str | Unset = ""
    verified: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        outcome_type = self.outcome_type

        description = self.description

        quantified_value = self.quantified_value

        measurement_date = self.measurement_date

        verified = self.verified

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "outcome_type": outcome_type,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if quantified_value is not UNSET:
            field_dict["quantified_value"] = quantified_value
        if measurement_date is not UNSET:
            field_dict["measurement_date"] = measurement_date
        if verified is not UNSET:
            field_dict["verified"] = verified

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        outcome_type = d.pop("outcome_type")

        description = d.pop("description", UNSET)

        quantified_value = d.pop("quantified_value", UNSET)

        measurement_date = d.pop("measurement_date", UNSET)

        verified = d.pop("verified", UNSET)

        record_outcome_request = cls(
            org_id=org_id,
            outcome_type=outcome_type,
            description=description,
            quantified_value=quantified_value,
            measurement_date=measurement_date,
            verified=verified,
        )

        record_outcome_request.additional_properties = d
        return record_outcome_request

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
