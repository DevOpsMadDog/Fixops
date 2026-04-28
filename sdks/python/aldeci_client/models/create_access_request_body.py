from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateAccessRequestBody")


@_attrs_define
class CreateAccessRequestBody:
    """
    Attributes:
        requester (str): User making the request
        resource_id (str | Unset): Target resource identifier Default: ''.
        resource_name (str | Unset): Human-readable resource name Default: ''.
        resource_type (str | Unset): database | application | server | network | cloud_resource | file_share | api
            Default: 'application'.
        access_type (str | Unset): read | write | admin | execute | delete | full_control Default: 'read'.
        justification (str | Unset): Business justification Default: ''.
        priority (str | Unset): urgent | high | normal | low Default: 'normal'.
        duration_days (int | Unset): Access duration in days Default: 30.
    """

    requester: str
    resource_id: str | Unset = ""
    resource_name: str | Unset = ""
    resource_type: str | Unset = "application"
    access_type: str | Unset = "read"
    justification: str | Unset = ""
    priority: str | Unset = "normal"
    duration_days: int | Unset = 30
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        requester = self.requester

        resource_id = self.resource_id

        resource_name = self.resource_name

        resource_type = self.resource_type

        access_type = self.access_type

        justification = self.justification

        priority = self.priority

        duration_days = self.duration_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "requester": requester,
            }
        )
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if resource_name is not UNSET:
            field_dict["resource_name"] = resource_name
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if access_type is not UNSET:
            field_dict["access_type"] = access_type
        if justification is not UNSET:
            field_dict["justification"] = justification
        if priority is not UNSET:
            field_dict["priority"] = priority
        if duration_days is not UNSET:
            field_dict["duration_days"] = duration_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        requester = d.pop("requester")

        resource_id = d.pop("resource_id", UNSET)

        resource_name = d.pop("resource_name", UNSET)

        resource_type = d.pop("resource_type", UNSET)

        access_type = d.pop("access_type", UNSET)

        justification = d.pop("justification", UNSET)

        priority = d.pop("priority", UNSET)

        duration_days = d.pop("duration_days", UNSET)

        create_access_request_body = cls(
            requester=requester,
            resource_id=resource_id,
            resource_name=resource_name,
            resource_type=resource_type,
            access_type=access_type,
            justification=justification,
            priority=priority,
            duration_days=duration_days,
        )

        create_access_request_body.additional_properties = d
        return create_access_request_body

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
