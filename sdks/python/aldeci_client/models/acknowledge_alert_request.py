from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="AcknowledgeAlertRequest")


@_attrs_define
class AcknowledgeAlertRequest:
    """
    Attributes:
        acknowledged_by (str): User or system acknowledging the alert
    """

    acknowledged_by: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        acknowledged_by = self.acknowledged_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "acknowledged_by": acknowledged_by,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        acknowledged_by = d.pop("acknowledged_by")

        acknowledge_alert_request = cls(
            acknowledged_by=acknowledged_by,
        )

        acknowledge_alert_request.additional_properties = d
        return acknowledge_alert_request

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
