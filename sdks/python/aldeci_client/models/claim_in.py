from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ClaimIn")


@_attrs_define
class ClaimIn:
    """
    Attributes:
        policy_id (str):
        incident_type (str | Unset):  Default: ''.
        incident_date (str | Unset):  Default: ''.
        estimated_loss (float | Unset):  Default: 0.0.
        adjuster (str | Unset):  Default: ''.
    """

    policy_id: str
    incident_type: str | Unset = ""
    incident_date: str | Unset = ""
    estimated_loss: float | Unset = 0.0
    adjuster: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_id = self.policy_id

        incident_type = self.incident_type

        incident_date = self.incident_date

        estimated_loss = self.estimated_loss

        adjuster = self.adjuster

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_id": policy_id,
            }
        )
        if incident_type is not UNSET:
            field_dict["incident_type"] = incident_type
        if incident_date is not UNSET:
            field_dict["incident_date"] = incident_date
        if estimated_loss is not UNSET:
            field_dict["estimated_loss"] = estimated_loss
        if adjuster is not UNSET:
            field_dict["adjuster"] = adjuster

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        policy_id = d.pop("policy_id")

        incident_type = d.pop("incident_type", UNSET)

        incident_date = d.pop("incident_date", UNSET)

        estimated_loss = d.pop("estimated_loss", UNSET)

        adjuster = d.pop("adjuster", UNSET)

        claim_in = cls(
            policy_id=policy_id,
            incident_type=incident_type,
            incident_date=incident_date,
            estimated_loss=estimated_loss,
            adjuster=adjuster,
        )

        claim_in.additional_properties = d
        return claim_in

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
