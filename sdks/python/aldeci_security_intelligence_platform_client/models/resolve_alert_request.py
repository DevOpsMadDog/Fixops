from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ResolveAlertRequest")


@_attrs_define
class ResolveAlertRequest:
    """
    Attributes:
        resolved_by (str): User or system resolving the alert
        resolution (str): Description of the resolution taken
    """

    resolved_by: str
    resolution: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resolved_by = self.resolved_by

        resolution = self.resolution

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "resolved_by": resolved_by,
                "resolution": resolution,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        resolved_by = d.pop("resolved_by")

        resolution = d.pop("resolution")

        resolve_alert_request = cls(
            resolved_by=resolved_by,
            resolution=resolution,
        )

        resolve_alert_request.additional_properties = d
        return resolve_alert_request

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
