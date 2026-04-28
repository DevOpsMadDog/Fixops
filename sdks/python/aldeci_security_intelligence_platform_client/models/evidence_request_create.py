from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EvidenceRequestCreate")


@_attrs_define
class EvidenceRequestCreate:
    """
    Attributes:
        framework (str | Unset): SOC2 | ISO27001 | PCI-DSS | HIPAA Default: 'SOC2'.
        control_id (str | Unset): Control identifier Default: ''.
        control_name (str | Unset): Human-readable control name Default: ''.
        description (str | Unset): What evidence is needed Default: ''.
        due_date (str | Unset): ISO date string Default: ''.
        assignee (str | Unset): Who is responsible Default: ''.
    """

    framework: str | Unset = "SOC2"
    control_id: str | Unset = ""
    control_name: str | Unset = ""
    description: str | Unset = ""
    due_date: str | Unset = ""
    assignee: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        control_id = self.control_id

        control_name = self.control_name

        description = self.description

        due_date = self.due_date

        assignee = self.assignee

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if framework is not UNSET:
            field_dict["framework"] = framework
        if control_id is not UNSET:
            field_dict["control_id"] = control_id
        if control_name is not UNSET:
            field_dict["control_name"] = control_name
        if description is not UNSET:
            field_dict["description"] = description
        if due_date is not UNSET:
            field_dict["due_date"] = due_date
        if assignee is not UNSET:
            field_dict["assignee"] = assignee

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        framework = d.pop("framework", UNSET)

        control_id = d.pop("control_id", UNSET)

        control_name = d.pop("control_name", UNSET)

        description = d.pop("description", UNSET)

        due_date = d.pop("due_date", UNSET)

        assignee = d.pop("assignee", UNSET)

        evidence_request_create = cls(
            framework=framework,
            control_id=control_id,
            control_name=control_name,
            description=description,
            due_date=due_date,
            assignee=assignee,
        )

        evidence_request_create.additional_properties = d
        return evidence_request_create

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
