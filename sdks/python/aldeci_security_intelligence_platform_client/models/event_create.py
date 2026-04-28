from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EventCreate")


@_attrs_define
class EventCreate:
    """
    Attributes:
        org_id (str):
        username (str):
        source_ip (str | Unset):  Default: ''.
        country (str | Unset):  Default: ''.
        city (str | Unset):  Default: ''.
        access_time (None | str | Unset):
        resource (str | Unset):  Default: ''.
        action (str | Unset):  Default: ''.
        success (int | Unset):  Default: 1.
    """

    org_id: str
    username: str
    source_ip: str | Unset = ""
    country: str | Unset = ""
    city: str | Unset = ""
    access_time: None | str | Unset = UNSET
    resource: str | Unset = ""
    action: str | Unset = ""
    success: int | Unset = 1
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        username = self.username

        source_ip = self.source_ip

        country = self.country

        city = self.city

        access_time: None | str | Unset
        if isinstance(self.access_time, Unset):
            access_time = UNSET
        else:
            access_time = self.access_time

        resource = self.resource

        action = self.action

        success = self.success

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "username": username,
            }
        )
        if source_ip is not UNSET:
            field_dict["source_ip"] = source_ip
        if country is not UNSET:
            field_dict["country"] = country
        if city is not UNSET:
            field_dict["city"] = city
        if access_time is not UNSET:
            field_dict["access_time"] = access_time
        if resource is not UNSET:
            field_dict["resource"] = resource
        if action is not UNSET:
            field_dict["action"] = action
        if success is not UNSET:
            field_dict["success"] = success

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        username = d.pop("username")

        source_ip = d.pop("source_ip", UNSET)

        country = d.pop("country", UNSET)

        city = d.pop("city", UNSET)

        def _parse_access_time(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        access_time = _parse_access_time(d.pop("access_time", UNSET))

        resource = d.pop("resource", UNSET)

        action = d.pop("action", UNSET)

        success = d.pop("success", UNSET)

        event_create = cls(
            org_id=org_id,
            username=username,
            source_ip=source_ip,
            country=country,
            city=city,
            access_time=access_time,
            resource=resource,
            action=action,
            success=success,
        )

        event_create.additional_properties = d
        return event_create

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
