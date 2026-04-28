from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectAnomalyRequest")


@_attrs_define
class DetectAnomalyRequest:
    """
    Attributes:
        user_id (str):
        org_id (str | Unset):  Default: 'default'.
        behavior_type (str | Unset):  Default: 'login_anomaly'.
        severity (str | Unset):  Default: 'medium'.
        observed_value (float | Unset):  Default: 0.0.
        baseline_value (float | Unset):  Default: 0.0.
        deviation_score (float | Unset):  Default: 0.0.
        description (str | Unset):  Default: ''.
        detected_at (None | str | Unset):
    """

    user_id: str
    org_id: str | Unset = "default"
    behavior_type: str | Unset = "login_anomaly"
    severity: str | Unset = "medium"
    observed_value: float | Unset = 0.0
    baseline_value: float | Unset = 0.0
    deviation_score: float | Unset = 0.0
    description: str | Unset = ""
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        org_id = self.org_id

        behavior_type = self.behavior_type

        severity = self.severity

        observed_value = self.observed_value

        baseline_value = self.baseline_value

        deviation_score = self.deviation_score

        description = self.description

        detected_at: None | str | Unset
        if isinstance(self.detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if behavior_type is not UNSET:
            field_dict["behavior_type"] = behavior_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if observed_value is not UNSET:
            field_dict["observed_value"] = observed_value
        if baseline_value is not UNSET:
            field_dict["baseline_value"] = baseline_value
        if deviation_score is not UNSET:
            field_dict["deviation_score"] = deviation_score
        if description is not UNSET:
            field_dict["description"] = description
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        org_id = d.pop("org_id", UNSET)

        behavior_type = d.pop("behavior_type", UNSET)

        severity = d.pop("severity", UNSET)

        observed_value = d.pop("observed_value", UNSET)

        baseline_value = d.pop("baseline_value", UNSET)

        deviation_score = d.pop("deviation_score", UNSET)

        description = d.pop("description", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        detect_anomaly_request = cls(
            user_id=user_id,
            org_id=org_id,
            behavior_type=behavior_type,
            severity=severity,
            observed_value=observed_value,
            baseline_value=baseline_value,
            deviation_score=deviation_score,
            description=description,
            detected_at=detected_at,
        )

        detect_anomaly_request.additional_properties = d
        return detect_anomaly_request

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
