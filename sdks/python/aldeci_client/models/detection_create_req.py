from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectionCreateReq")


@_attrs_define
class DetectionCreateReq:
    """
    Attributes:
        org_id (str):
        package_id (str):
        detection_type (str):
        confidence_score (float | Unset):  Default: 0.0.
        evidence (None | str | Unset):
        severity (str | Unset):  Default: 'medium'.
        detected_at (None | str | Unset):
    """

    org_id: str
    package_id: str
    detection_type: str
    confidence_score: float | Unset = 0.0
    evidence: None | str | Unset = UNSET
    severity: str | Unset = "medium"
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        package_id = self.package_id

        detection_type = self.detection_type

        confidence_score = self.confidence_score

        evidence: None | str | Unset
        if isinstance(self.evidence, Unset):
            evidence = UNSET
        else:
            evidence = self.evidence

        severity = self.severity

        detected_at: None | str | Unset
        if isinstance(self.detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "package_id": package_id,
                "detection_type": detection_type,
            }
        )
        if confidence_score is not UNSET:
            field_dict["confidence_score"] = confidence_score
        if evidence is not UNSET:
            field_dict["evidence"] = evidence
        if severity is not UNSET:
            field_dict["severity"] = severity
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        package_id = d.pop("package_id")

        detection_type = d.pop("detection_type")

        confidence_score = d.pop("confidence_score", UNSET)

        def _parse_evidence(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        evidence = _parse_evidence(d.pop("evidence", UNSET))

        severity = d.pop("severity", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        detection_create_req = cls(
            org_id=org_id,
            package_id=package_id,
            detection_type=detection_type,
            confidence_score=confidence_score,
            evidence=evidence,
            severity=severity,
            detected_at=detected_at,
        )

        detection_create_req.additional_properties = d
        return detection_create_req

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
