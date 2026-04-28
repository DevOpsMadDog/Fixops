from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddControlGapRequest")


@_attrs_define
class AddControlGapRequest:
    """
    Attributes:
        assessment_id (str): Parent assessment ID
        control_id (str): Framework control identifier
        control_name (str): Human-readable control name
        severity (str): critical|high|medium|low
        domain (str | Unset): Control domain/category Default: ''.
        gap_description (str | Unset): Description of the gap Default: ''.
        current_state (str | Unset): Current implementation state Default: ''.
        required_state (str | Unset): Required implementation state Default: ''.
        remediation_effort (int | Unset): Estimated remediation hours Default: 0.
    """

    assessment_id: str
    control_id: str
    control_name: str
    severity: str
    domain: str | Unset = ""
    gap_description: str | Unset = ""
    current_state: str | Unset = ""
    required_state: str | Unset = ""
    remediation_effort: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        assessment_id = self.assessment_id

        control_id = self.control_id

        control_name = self.control_name

        severity = self.severity

        domain = self.domain

        gap_description = self.gap_description

        current_state = self.current_state

        required_state = self.required_state

        remediation_effort = self.remediation_effort

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "assessment_id": assessment_id,
                "control_id": control_id,
                "control_name": control_name,
                "severity": severity,
            }
        )
        if domain is not UNSET:
            field_dict["domain"] = domain
        if gap_description is not UNSET:
            field_dict["gap_description"] = gap_description
        if current_state is not UNSET:
            field_dict["current_state"] = current_state
        if required_state is not UNSET:
            field_dict["required_state"] = required_state
        if remediation_effort is not UNSET:
            field_dict["remediation_effort"] = remediation_effort

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        assessment_id = d.pop("assessment_id")

        control_id = d.pop("control_id")

        control_name = d.pop("control_name")

        severity = d.pop("severity")

        domain = d.pop("domain", UNSET)

        gap_description = d.pop("gap_description", UNSET)

        current_state = d.pop("current_state", UNSET)

        required_state = d.pop("required_state", UNSET)

        remediation_effort = d.pop("remediation_effort", UNSET)

        add_control_gap_request = cls(
            assessment_id=assessment_id,
            control_id=control_id,
            control_name=control_name,
            severity=severity,
            domain=domain,
            gap_description=gap_description,
            current_state=current_state,
            required_state=required_state,
            remediation_effort=remediation_effort,
        )

        add_control_gap_request.additional_properties = d
        return add_control_gap_request

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
