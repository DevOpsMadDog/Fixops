from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordDetectionRequest")


@_attrs_define
class RecordDetectionRequest:
    """
    Attributes:
        detection_name (str): Name of the detection
        model_type (str | Unset): anomaly_detection | classification | nlp | graph_ml | time_series | rule_based |
            ensemble Default: 'rule_based'.
        confidence_score (float | Unset):  Default: 0.0.
        severity (str | Unset): critical | high | medium | low Default: 'medium'.
        source_data_type (str | Unset): logs | network | endpoint | identity | cloud | email | file Default: 'logs'.
    """

    detection_name: str
    model_type: str | Unset = "rule_based"
    confidence_score: float | Unset = 0.0
    severity: str | Unset = "medium"
    source_data_type: str | Unset = "logs"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        detection_name = self.detection_name

        model_type = self.model_type

        confidence_score = self.confidence_score

        severity = self.severity

        source_data_type = self.source_data_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "detection_name": detection_name,
            }
        )
        if model_type is not UNSET:
            field_dict["model_type"] = model_type
        if confidence_score is not UNSET:
            field_dict["confidence_score"] = confidence_score
        if severity is not UNSET:
            field_dict["severity"] = severity
        if source_data_type is not UNSET:
            field_dict["source_data_type"] = source_data_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        detection_name = d.pop("detection_name")

        model_type = d.pop("model_type", UNSET)

        confidence_score = d.pop("confidence_score", UNSET)

        severity = d.pop("severity", UNSET)

        source_data_type = d.pop("source_data_type", UNSET)

        record_detection_request = cls(
            detection_name=detection_name,
            model_type=model_type,
            confidence_score=confidence_score,
            severity=severity,
            source_data_type=source_data_type,
        )

        record_detection_request.additional_properties = d
        return record_detection_request

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
