from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SlackComplianceFailureRequest")


@_attrs_define
class SlackComplianceFailureRequest:
    """For compliance failure notification via the API.

    Attributes:
        framework (str): Compliance framework (e.g. SOC2, PCI-DSS)
        control (str): Failed control ID or name
        severity (str | Unset): critical | high | medium | low Default: 'high'.
        failure_id (None | str | Unset): Failure record ID
        description (None | str | Unset): Failure description
        remediation (None | str | Unset): Recommended remediation
    """

    framework: str
    control: str
    severity: str | Unset = "high"
    failure_id: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    remediation: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        control = self.control

        severity = self.severity

        failure_id: None | str | Unset
        if isinstance(self.failure_id, Unset):
            failure_id = UNSET
        else:
            failure_id = self.failure_id

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        remediation: None | str | Unset
        if isinstance(self.remediation, Unset):
            remediation = UNSET
        else:
            remediation = self.remediation

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
                "control": control,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if failure_id is not UNSET:
            field_dict["failure_id"] = failure_id
        if description is not UNSET:
            field_dict["description"] = description
        if remediation is not UNSET:
            field_dict["remediation"] = remediation

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        framework = d.pop("framework")

        control = d.pop("control")

        severity = d.pop("severity", UNSET)

        def _parse_failure_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        failure_id = _parse_failure_id(d.pop("failure_id", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_remediation(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation = _parse_remediation(d.pop("remediation", UNSET))

        slack_compliance_failure_request = cls(
            framework=framework,
            control=control,
            severity=severity,
            failure_id=failure_id,
            description=description,
            remediation=remediation,
        )

        slack_compliance_failure_request.additional_properties = d
        return slack_compliance_failure_request

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
