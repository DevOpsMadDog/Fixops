from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectionCreate")


@_attrs_define
class DetectionCreate:
    """
    Attributes:
        org_id (str):
        detection_name (str):
        detection_type (str | Unset):  Default: 'behavioral'.
        affected_systems (list[str] | Unset):
        file_extensions (list[str] | Unset):
        confidence (float | Unset):  Default: 0.5.
        severity (str | Unset):  Default: 'high'.
    """

    org_id: str
    detection_name: str
    detection_type: str | Unset = "behavioral"
    affected_systems: list[str] | Unset = UNSET
    file_extensions: list[str] | Unset = UNSET
    confidence: float | Unset = 0.5
    severity: str | Unset = "high"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        detection_name = self.detection_name

        detection_type = self.detection_type

        affected_systems: list[str] | Unset = UNSET
        if not isinstance(self.affected_systems, Unset):
            affected_systems = self.affected_systems

        file_extensions: list[str] | Unset = UNSET
        if not isinstance(self.file_extensions, Unset):
            file_extensions = self.file_extensions

        confidence = self.confidence

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "detection_name": detection_name,
            }
        )
        if detection_type is not UNSET:
            field_dict["detection_type"] = detection_type
        if affected_systems is not UNSET:
            field_dict["affected_systems"] = affected_systems
        if file_extensions is not UNSET:
            field_dict["file_extensions"] = file_extensions
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        detection_name = d.pop("detection_name")

        detection_type = d.pop("detection_type", UNSET)

        affected_systems = cast(list[str], d.pop("affected_systems", UNSET))

        file_extensions = cast(list[str], d.pop("file_extensions", UNSET))

        confidence = d.pop("confidence", UNSET)

        severity = d.pop("severity", UNSET)

        detection_create = cls(
            org_id=org_id,
            detection_name=detection_name,
            detection_type=detection_type,
            affected_systems=affected_systems,
            file_extensions=file_extensions,
            confidence=confidence,
            severity=severity,
        )

        detection_create.additional_properties = d
        return detection_create

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
