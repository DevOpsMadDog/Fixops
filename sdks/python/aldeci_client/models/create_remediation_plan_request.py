from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CreateRemediationPlanRequest")


@_attrs_define
class CreateRemediationPlanRequest:
    """
    Attributes:
        gap_id (str): Control gap ID to remediate
        plan_description (str): Remediation plan description
        owner (str): Owner responsible for remediation
        target_date (str): Target completion date (ISO)
    """

    gap_id: str
    plan_description: str
    owner: str
    target_date: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        gap_id = self.gap_id

        plan_description = self.plan_description

        owner = self.owner

        target_date = self.target_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "gap_id": gap_id,
                "plan_description": plan_description,
                "owner": owner,
                "target_date": target_date,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        gap_id = d.pop("gap_id")

        plan_description = d.pop("plan_description")

        owner = d.pop("owner")

        target_date = d.pop("target_date")

        create_remediation_plan_request = cls(
            gap_id=gap_id,
            plan_description=plan_description,
            owner=owner,
            target_date=target_date,
        )

        create_remediation_plan_request.additional_properties = d
        return create_remediation_plan_request

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
