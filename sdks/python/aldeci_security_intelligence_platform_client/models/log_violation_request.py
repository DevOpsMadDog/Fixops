from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LogViolationRequest")


@_attrs_define
class LogViolationRequest:
    """
    Attributes:
        asset_id (str | Unset):  Default: ''.
        policy_id (str | Unset):  Default: ''.
        violation_type (str | Unset):  Default: ''.
        description (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        detected_at (None | str | Unset):
    """

    asset_id: str | Unset = ""
    policy_id: str | Unset = ""
    violation_type: str | Unset = ""
    description: str | Unset = ""
    severity: str | Unset = "medium"
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        policy_id = self.policy_id

        violation_type = self.violation_type

        description = self.description

        severity = self.severity

        detected_at: None | str | Unset
        if isinstance(self.detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if asset_id is not UNSET:
            field_dict["asset_id"] = asset_id
        if policy_id is not UNSET:
            field_dict["policy_id"] = policy_id
        if violation_type is not UNSET:
            field_dict["violation_type"] = violation_type
        if description is not UNSET:
            field_dict["description"] = description
        if severity is not UNSET:
            field_dict["severity"] = severity
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_id = d.pop("asset_id", UNSET)

        policy_id = d.pop("policy_id", UNSET)

        violation_type = d.pop("violation_type", UNSET)

        description = d.pop("description", UNSET)

        severity = d.pop("severity", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        log_violation_request = cls(
            asset_id=asset_id,
            policy_id=policy_id,
            violation_type=violation_type,
            description=description,
            severity=severity,
            detected_at=detected_at,
        )

        log_violation_request.additional_properties = d
        return log_violation_request

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
