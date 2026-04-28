from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DriftCreate")


@_attrs_define
class DriftCreate:
    """
    Attributes:
        resource_id (str): Cloud resource identifier
        drift_type (str | Unset): config_changed / resource_deleted / new_resource / tag_missing / permission_widened
            Default: 'config_changed'.
        severity (str | Unset): critical / high / medium / low Default: 'medium'.
        expected_value (str | Unset): Expected configuration value Default: ''.
        actual_value (str | Unset): Actual observed configuration value Default: ''.
        detected_at (None | str | Unset): ISO 8601 detection timestamp
    """

    resource_id: str
    drift_type: str | Unset = "config_changed"
    severity: str | Unset = "medium"
    expected_value: str | Unset = ""
    actual_value: str | Unset = ""
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resource_id = self.resource_id

        drift_type = self.drift_type

        severity = self.severity

        expected_value = self.expected_value

        actual_value = self.actual_value

        detected_at: None | str | Unset
        if isinstance(self.detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "resource_id": resource_id,
            }
        )
        if drift_type is not UNSET:
            field_dict["drift_type"] = drift_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if expected_value is not UNSET:
            field_dict["expected_value"] = expected_value
        if actual_value is not UNSET:
            field_dict["actual_value"] = actual_value
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        resource_id = d.pop("resource_id")

        drift_type = d.pop("drift_type", UNSET)

        severity = d.pop("severity", UNSET)

        expected_value = d.pop("expected_value", UNSET)

        actual_value = d.pop("actual_value", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        drift_create = cls(
            resource_id=resource_id,
            drift_type=drift_type,
            severity=severity,
            expected_value=expected_value,
            actual_value=actual_value,
            detected_at=detected_at,
        )

        drift_create.additional_properties = d
        return drift_create

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
