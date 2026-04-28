from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordAssessmentRequest")


@_attrs_define
class RecordAssessmentRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        domain (str): Security domain
        capability (str): Capability being assessed
        maturity_level (int): Current maturity level (1–max_level)
        max_level (int | Unset): Maximum maturity level (default 5) Default: 5.
        evidence (str | Unset): Supporting evidence Default: ''.
        assessor (str | Unset): Who performed the assessment Default: ''.
        next_review (str | Unset): ISO-8601 date/time for next review Default: ''.
    """

    org_id: str
    domain: str
    capability: str
    maturity_level: int
    max_level: int | Unset = 5
    evidence: str | Unset = ""
    assessor: str | Unset = ""
    next_review: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        domain = self.domain

        capability = self.capability

        maturity_level = self.maturity_level

        max_level = self.max_level

        evidence = self.evidence

        assessor = self.assessor

        next_review = self.next_review

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "domain": domain,
                "capability": capability,
                "maturity_level": maturity_level,
            }
        )
        if max_level is not UNSET:
            field_dict["max_level"] = max_level
        if evidence is not UNSET:
            field_dict["evidence"] = evidence
        if assessor is not UNSET:
            field_dict["assessor"] = assessor
        if next_review is not UNSET:
            field_dict["next_review"] = next_review

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        domain = d.pop("domain")

        capability = d.pop("capability")

        maturity_level = d.pop("maturity_level")

        max_level = d.pop("max_level", UNSET)

        evidence = d.pop("evidence", UNSET)

        assessor = d.pop("assessor", UNSET)

        next_review = d.pop("next_review", UNSET)

        record_assessment_request = cls(
            org_id=org_id,
            domain=domain,
            capability=capability,
            maturity_level=maturity_level,
            max_level=max_level,
            evidence=evidence,
            assessor=assessor,
            next_review=next_review,
        )

        record_assessment_request.additional_properties = d
        return record_assessment_request

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
