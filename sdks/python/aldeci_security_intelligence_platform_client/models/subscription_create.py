from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SubscriptionCreate")


@_attrs_define
class SubscriptionCreate:
    """
    Attributes:
        subscription_value (str):
        subscription_type (str | Unset):  Default: 'vendor'.
        notify_severity_min (str | Unset):  Default: 'high'.
    """

    subscription_value: str
    subscription_type: str | Unset = "vendor"
    notify_severity_min: str | Unset = "high"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        subscription_value = self.subscription_value

        subscription_type = self.subscription_type

        notify_severity_min = self.notify_severity_min

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "subscription_value": subscription_value,
            }
        )
        if subscription_type is not UNSET:
            field_dict["subscription_type"] = subscription_type
        if notify_severity_min is not UNSET:
            field_dict["notify_severity_min"] = notify_severity_min

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        subscription_value = d.pop("subscription_value")

        subscription_type = d.pop("subscription_type", UNSET)

        notify_severity_min = d.pop("notify_severity_min", UNSET)

        subscription_create = cls(
            subscription_value=subscription_value,
            subscription_type=subscription_type,
            notify_severity_min=notify_severity_min,
        )

        subscription_create.additional_properties = d
        return subscription_create

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
