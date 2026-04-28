from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordControlRequest")


@_attrs_define
class RecordControlRequest:
    """
    Attributes:
        benchmark_id (str): Parent benchmark ID
        result (str): Result: pass, fail, partial, not_applicable
        severity (str): Severity: critical, high, medium, low
        org_id (str | Unset):  Default: 'default'.
        control_id (str | Unset): Control identifier (e.g. CIS 1.1) Default: ''.
        title (str | Unset): Control title Default: ''.
        description (str | Unset): Control description Default: ''.
        remediation (str | Unset): Remediation guidance Default: ''.
    """

    benchmark_id: str
    result: str
    severity: str
    org_id: str | Unset = "default"
    control_id: str | Unset = ""
    title: str | Unset = ""
    description: str | Unset = ""
    remediation: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        benchmark_id = self.benchmark_id

        result = self.result

        severity = self.severity

        org_id = self.org_id

        control_id = self.control_id

        title = self.title

        description = self.description

        remediation = self.remediation

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "benchmark_id": benchmark_id,
                "result": result,
                "severity": severity,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if control_id is not UNSET:
            field_dict["control_id"] = control_id
        if title is not UNSET:
            field_dict["title"] = title
        if description is not UNSET:
            field_dict["description"] = description
        if remediation is not UNSET:
            field_dict["remediation"] = remediation

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        benchmark_id = d.pop("benchmark_id")

        result = d.pop("result")

        severity = d.pop("severity")

        org_id = d.pop("org_id", UNSET)

        control_id = d.pop("control_id", UNSET)

        title = d.pop("title", UNSET)

        description = d.pop("description", UNSET)

        remediation = d.pop("remediation", UNSET)

        record_control_request = cls(
            benchmark_id=benchmark_id,
            result=result,
            severity=severity,
            org_id=org_id,
            control_id=control_id,
            title=title,
            description=description,
            remediation=remediation,
        )

        record_control_request.additional_properties = d
        return record_control_request

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
