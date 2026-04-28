from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateAlertPolicyRequest")


@_attrs_define
class CreateAlertPolicyRequest:
    """
    Attributes:
        name (str): Human-readable policy name
        severity (str | Unset): critical | high | medium | low Default: 'medium'.
        condition_type (str | Unset): threshold | anomaly | pattern | schedule Default: 'threshold'.
        channels (list[str] | Unset): Delivery channels: email, slack, pagerduty, webhook
        enabled (bool | Unset): Whether the policy is active Default: True.
    """

    name: str
    severity: str | Unset = "medium"
    condition_type: str | Unset = "threshold"
    channels: list[str] | Unset = UNSET
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        severity = self.severity

        condition_type = self.condition_type

        channels: list[str] | Unset = UNSET
        if not isinstance(self.channels, Unset):
            channels = self.channels

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if condition_type is not UNSET:
            field_dict["condition_type"] = condition_type
        if channels is not UNSET:
            field_dict["channels"] = channels
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        severity = d.pop("severity", UNSET)

        condition_type = d.pop("condition_type", UNSET)

        channels = cast(list[str], d.pop("channels", UNSET))

        enabled = d.pop("enabled", UNSET)

        create_alert_policy_request = cls(
            name=name,
            severity=severity,
            condition_type=condition_type,
            channels=channels,
            enabled=enabled,
        )

        create_alert_policy_request.additional_properties = d
        return create_alert_policy_request

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
