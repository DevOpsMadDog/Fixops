from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessmentResultItem")


@_attrs_define
class AssessmentResultItem:
    """
    Attributes:
        control_id (str): Control identifier
        status (str): pass | fail | skip
        control_name (str | Unset): Control name Default: ''.
        actual_value (str | Unset): Observed configuration value Default: ''.
        deviation (str | Unset): Description of deviation from expected Default: ''.
        severity (str | Unset): critical | high | medium | low Default: 'medium'.
    """

    control_id: str
    status: str
    control_name: str | Unset = ""
    actual_value: str | Unset = ""
    deviation: str | Unset = ""
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_id = self.control_id

        status = self.status

        control_name = self.control_name

        actual_value = self.actual_value

        deviation = self.deviation

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_id": control_id,
                "status": status,
            }
        )
        if control_name is not UNSET:
            field_dict["control_name"] = control_name
        if actual_value is not UNSET:
            field_dict["actual_value"] = actual_value
        if deviation is not UNSET:
            field_dict["deviation"] = deviation
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_id = d.pop("control_id")

        status = d.pop("status")

        control_name = d.pop("control_name", UNSET)

        actual_value = d.pop("actual_value", UNSET)

        deviation = d.pop("deviation", UNSET)

        severity = d.pop("severity", UNSET)

        assessment_result_item = cls(
            control_id=control_id,
            status=status,
            control_name=control_name,
            actual_value=actual_value,
            deviation=deviation,
            severity=severity,
        )

        assessment_result_item.additional_properties = d
        return assessment_result_item

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
