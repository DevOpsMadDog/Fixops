from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ProvisionRequest")


@_attrs_define
class ProvisionRequest:
    """
    Attributes:
        event_type (str): Security event type
        integrations (list[str] | Unset): Output integrations, e.g. ["slack", "jira", "pagerduty"]
    """

    event_type: str
    integrations: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_type = self.event_type

        integrations: list[str] | Unset = UNSET
        if not isinstance(self.integrations, Unset):
            integrations = self.integrations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event_type": event_type,
            }
        )
        if integrations is not UNSET:
            field_dict["integrations"] = integrations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        event_type = d.pop("event_type")

        integrations = cast(list[str], d.pop("integrations", UNSET))

        provision_request = cls(
            event_type=event_type,
            integrations=integrations,
        )

        provision_request.additional_properties = d
        return provision_request

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
