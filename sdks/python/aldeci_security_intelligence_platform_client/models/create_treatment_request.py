from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.treatment_action import TreatmentAction
from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateTreatmentRequest")


@_attrs_define
class CreateTreatmentRequest:
    """
    Attributes:
        risk_id (str): ID of the risk being treated
        action (TreatmentAction):
        description (str): Treatment description
        owner (str | Unset):  Default: ''.
        target_date (str | Unset): ISO date string for target completion Default: ''.
        notes (str | Unset):  Default: ''.
    """

    risk_id: str
    action: TreatmentAction
    description: str
    owner: str | Unset = ""
    target_date: str | Unset = ""
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        risk_id = self.risk_id

        action = self.action.value

        description = self.description

        owner = self.owner

        target_date = self.target_date

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "risk_id": risk_id,
                "action": action,
                "description": description,
            }
        )
        if owner is not UNSET:
            field_dict["owner"] = owner
        if target_date is not UNSET:
            field_dict["target_date"] = target_date
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        risk_id = d.pop("risk_id")

        action = TreatmentAction(d.pop("action"))

        description = d.pop("description")

        owner = d.pop("owner", UNSET)

        target_date = d.pop("target_date", UNSET)

        notes = d.pop("notes", UNSET)

        create_treatment_request = cls(
            risk_id=risk_id,
            action=action,
            description=description,
            owner=owner,
            target_date=target_date,
            notes=notes,
        )

        create_treatment_request.additional_properties = d
        return create_treatment_request

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
