from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectionRecord")


@_attrs_define
class DetectionRecord:
    """
    Attributes:
        technique (str):
        detected_by (str):
        detection_time_seconds (int | Unset):  Default: 0.
        true_positive (bool | Unset):  Default: True.
    """

    technique: str
    detected_by: str
    detection_time_seconds: int | Unset = 0
    true_positive: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        technique = self.technique

        detected_by = self.detected_by

        detection_time_seconds = self.detection_time_seconds

        true_positive = self.true_positive

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "technique": technique,
                "detected_by": detected_by,
            }
        )
        if detection_time_seconds is not UNSET:
            field_dict["detection_time_seconds"] = detection_time_seconds
        if true_positive is not UNSET:
            field_dict["true_positive"] = true_positive

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        technique = d.pop("technique")

        detected_by = d.pop("detected_by")

        detection_time_seconds = d.pop("detection_time_seconds", UNSET)

        true_positive = d.pop("true_positive", UNSET)

        detection_record = cls(
            technique=technique,
            detected_by=detected_by,
            detection_time_seconds=detection_time_seconds,
            true_positive=true_positive,
        )

        detection_record.additional_properties = d
        return detection_record

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
