from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessmentData")


@_attrs_define
class AssessmentData:
    """
    Attributes:
        auth_controls (bool | Unset):  Default: False.
        input_validation (bool | Unset):  Default: False.
        encryption (bool | Unset):  Default: False.
        dependency_scan (bool | Unset):  Default: True.
        sast_findings (int | Unset):  Default: 0.
        dast_findings (int | Unset):  Default: 0.
        internet_exposed (bool | Unset):  Default: False.
    """

    auth_controls: bool | Unset = False
    input_validation: bool | Unset = False
    encryption: bool | Unset = False
    dependency_scan: bool | Unset = True
    sast_findings: int | Unset = 0
    dast_findings: int | Unset = 0
    internet_exposed: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        auth_controls = self.auth_controls

        input_validation = self.input_validation

        encryption = self.encryption

        dependency_scan = self.dependency_scan

        sast_findings = self.sast_findings

        dast_findings = self.dast_findings

        internet_exposed = self.internet_exposed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if auth_controls is not UNSET:
            field_dict["auth_controls"] = auth_controls
        if input_validation is not UNSET:
            field_dict["input_validation"] = input_validation
        if encryption is not UNSET:
            field_dict["encryption"] = encryption
        if dependency_scan is not UNSET:
            field_dict["dependency_scan"] = dependency_scan
        if sast_findings is not UNSET:
            field_dict["sast_findings"] = sast_findings
        if dast_findings is not UNSET:
            field_dict["dast_findings"] = dast_findings
        if internet_exposed is not UNSET:
            field_dict["internet_exposed"] = internet_exposed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        auth_controls = d.pop("auth_controls", UNSET)

        input_validation = d.pop("input_validation", UNSET)

        encryption = d.pop("encryption", UNSET)

        dependency_scan = d.pop("dependency_scan", UNSET)

        sast_findings = d.pop("sast_findings", UNSET)

        dast_findings = d.pop("dast_findings", UNSET)

        internet_exposed = d.pop("internet_exposed", UNSET)

        assessment_data = cls(
            auth_controls=auth_controls,
            input_validation=input_validation,
            encryption=encryption,
            dependency_scan=dependency_scan,
            sast_findings=sast_findings,
            dast_findings=dast_findings,
            internet_exposed=internet_exposed,
        )

        assessment_data.additional_properties = d
        return assessment_data

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
