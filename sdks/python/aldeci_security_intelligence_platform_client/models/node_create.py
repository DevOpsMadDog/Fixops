from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="NodeCreate")


@_attrs_define
class NodeCreate:
    """
    Attributes:
        org_id (str):
        node_type (str | Unset):  Default: 'server'.
        hostname (str | Unset):  Default: ''.
        ip (str | Unset):  Default: ''.
        os (str | Unset):  Default: ''.
        location (str | Unset):  Default: ''.
        criticality (str | Unset):  Default: 'medium'.
        tags (list[str] | Unset):
    """

    org_id: str
    node_type: str | Unset = "server"
    hostname: str | Unset = ""
    ip: str | Unset = ""
    os: str | Unset = ""
    location: str | Unset = ""
    criticality: str | Unset = "medium"
    tags: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        node_type = self.node_type

        hostname = self.hostname

        ip = self.ip

        os = self.os

        location = self.location

        criticality = self.criticality

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if node_type is not UNSET:
            field_dict["node_type"] = node_type
        if hostname is not UNSET:
            field_dict["hostname"] = hostname
        if ip is not UNSET:
            field_dict["ip"] = ip
        if os is not UNSET:
            field_dict["os"] = os
        if location is not UNSET:
            field_dict["location"] = location
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        node_type = d.pop("node_type", UNSET)

        hostname = d.pop("hostname", UNSET)

        ip = d.pop("ip", UNSET)

        os = d.pop("os", UNSET)

        location = d.pop("location", UNSET)

        criticality = d.pop("criticality", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        node_create = cls(
            org_id=org_id,
            node_type=node_type,
            hostname=hostname,
            ip=ip,
            os=os,
            location=location,
            criticality=criticality,
            tags=tags,
        )

        node_create.additional_properties = d
        return node_create

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
