from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LogFailureRequest")


@_attrs_define
class LogFailureRequest:
    """
    Attributes:
        control_id (str):
        test_id (None | str | Unset):
        failure_type (str | Unset):  Default: 'gap'.
        severity (str | Unset):  Default: 'medium'.
        description (str | Unset):  Default: ''.
        detected_at (None | str | Unset):
    """

    control_id: str
    test_id: None | str | Unset = UNSET
    failure_type: str | Unset = "gap"
    severity: str | Unset = "medium"
    description: str | Unset = ""
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_id = self.control_id

        test_id: None | str | Unset
        if isinstance(self.test_id, Unset):
            test_id = UNSET
        else:
            test_id = self.test_id

        failure_type = self.failure_type

        severity = self.severity

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
                "control_id": control_id,
            }
        )
        if test_id is not UNSET:
            field_dict["test_id"] = test_id
        if failure_type is not UNSET:
            field_dict["failure_type"] = failure_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_id = d.pop("control_id")

        def _parse_test_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        test_id = _parse_test_id(d.pop("test_id", UNSET))

        failure_type = d.pop("failure_type", UNSET)

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        log_failure_request = cls(
            control_id=control_id,
            test_id=test_id,
            failure_type=failure_type,
            severity=severity,
            description=description,
            detected_at=detected_at,
        )

        log_failure_request.additional_properties = d
        return log_failure_request

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
