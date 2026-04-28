from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExposureCreate")


@_attrs_define
class ExposureCreate:
    """
    Attributes:
        title (str):
        exposure_type (str | Unset):  Default: 'open_port'.
        severity (str | Unset):  Default: 'medium'.
        description (str | Unset):  Default: ''.
        evidence (str | Unset):  Default: ''.
        cvss_score (float | Unset):  Default: 0.0.
        remediation (str | Unset):  Default: ''.
        first_detected (None | str | Unset):
        last_seen (None | str | Unset):
    """

    title: str
    exposure_type: str | Unset = "open_port"
    severity: str | Unset = "medium"
    description: str | Unset = ""
    evidence: str | Unset = ""
    cvss_score: float | Unset = 0.0
    remediation: str | Unset = ""
    first_detected: None | str | Unset = UNSET
    last_seen: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        exposure_type = self.exposure_type

        severity = self.severity

        description = self.description

        evidence = self.evidence

        cvss_score = self.cvss_score

        remediation = self.remediation

        first_detected: None | str | Unset
        if isinstance(self.first_detected, Unset):
            first_detected = UNSET
        else:
            first_detected = self.first_detected

        last_seen: None | str | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if exposure_type is not UNSET:
            field_dict["exposure_type"] = exposure_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if evidence is not UNSET:
            field_dict["evidence"] = evidence
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if first_detected is not UNSET:
            field_dict["first_detected"] = first_detected
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        exposure_type = d.pop("exposure_type", UNSET)

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        evidence = d.pop("evidence", UNSET)

        cvss_score = d.pop("cvss_score", UNSET)

        remediation = d.pop("remediation", UNSET)

        def _parse_first_detected(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_detected = _parse_first_detected(d.pop("first_detected", UNSET))

        def _parse_last_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        exposure_create = cls(
            title=title,
            exposure_type=exposure_type,
            severity=severity,
            description=description,
            evidence=evidence,
            cvss_score=cvss_score,
            remediation=remediation,
            first_detected=first_detected,
            last_seen=last_seen,
        )

        exposure_create.additional_properties = d
        return exposure_create

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
