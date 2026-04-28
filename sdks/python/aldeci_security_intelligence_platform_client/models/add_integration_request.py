from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddIntegrationRequest")


@_attrs_define
class AddIntegrationRequest:
    """
    Attributes:
        tool_id (str): Source tool ID
        integrated_with (str): Target tool or system name
        integration_type (str): api | syslog | webhook | agent | manual
        status (None | str | Unset): active | inactive | broken | pending Default: 'pending'.
    """

    tool_id: str
    integrated_with: str
    integration_type: str
    status: None | str | Unset = "pending"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tool_id = self.tool_id

        integrated_with = self.integrated_with

        integration_type = self.integration_type

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tool_id": tool_id,
                "integrated_with": integrated_with,
                "integration_type": integration_type,
            }
        )
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tool_id = d.pop("tool_id")

        integrated_with = d.pop("integrated_with")

        integration_type = d.pop("integration_type")

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        add_integration_request = cls(
            tool_id=tool_id,
            integrated_with=integrated_with,
            integration_type=integration_type,
            status=status,
        )

        add_integration_request.additional_properties = d
        return add_integration_request

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
