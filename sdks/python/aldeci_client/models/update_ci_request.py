from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateCIRequest")


@_attrs_define
class UpdateCIRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        name (None | str | Unset):
        category (None | str | Unset):
        owner (None | str | Unset):
        status (None | str | Unset):
        environment (None | str | Unset):
        location (None | str | Unset):
        ip_address (None | str | Unset):
        os (None | str | Unset):
        version (None | str | Unset):
        criticality (None | str | Unset):
        support_tier (None | str | Unset):
        tags (list[str] | None | Unset):
    """

    org_id: str
    name: None | str | Unset = UNSET
    category: None | str | Unset = UNSET
    owner: None | str | Unset = UNSET
    status: None | str | Unset = UNSET
    environment: None | str | Unset = UNSET
    location: None | str | Unset = UNSET
    ip_address: None | str | Unset = UNSET
    os: None | str | Unset = UNSET
    version: None | str | Unset = UNSET
    criticality: None | str | Unset = UNSET
    support_tier: None | str | Unset = UNSET
    tags: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        category: None | str | Unset
        if isinstance(self.category, Unset):
            category = UNSET
        else:
            category = self.category

        owner: None | str | Unset
        if isinstance(self.owner, Unset):
            owner = UNSET
        else:
            owner = self.owner

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        environment: None | str | Unset
        if isinstance(self.environment, Unset):
            environment = UNSET
        else:
            environment = self.environment

        location: None | str | Unset
        if isinstance(self.location, Unset):
            location = UNSET
        else:
            location = self.location

        ip_address: None | str | Unset
        if isinstance(self.ip_address, Unset):
            ip_address = UNSET
        else:
            ip_address = self.ip_address

        os: None | str | Unset
        if isinstance(self.os, Unset):
            os = UNSET
        else:
            os = self.os

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        criticality: None | str | Unset
        if isinstance(self.criticality, Unset):
            criticality = UNSET
        else:
            criticality = self.criticality

        support_tier: None | str | Unset
        if isinstance(self.support_tier, Unset):
            support_tier = UNSET
        else:
            support_tier = self.support_tier

        tags: list[str] | None | Unset
        if isinstance(self.tags, Unset):
            tags = UNSET
        elif isinstance(self.tags, list):
            tags = self.tags

        else:
            tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if name is not UNSET:
            field_dict["name"] = name
        if category is not UNSET:
            field_dict["category"] = category
        if owner is not UNSET:
            field_dict["owner"] = owner
        if status is not UNSET:
            field_dict["status"] = status
        if environment is not UNSET:
            field_dict["environment"] = environment
        if location is not UNSET:
            field_dict["location"] = location
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if os is not UNSET:
            field_dict["os"] = os
        if version is not UNSET:
            field_dict["version"] = version
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if support_tier is not UNSET:
            field_dict["support_tier"] = support_tier
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_category(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        category = _parse_category(d.pop("category", UNSET))

        def _parse_owner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner = _parse_owner(d.pop("owner", UNSET))

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_environment(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        environment = _parse_environment(d.pop("environment", UNSET))

        def _parse_location(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        location = _parse_location(d.pop("location", UNSET))

        def _parse_ip_address(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ip_address = _parse_ip_address(d.pop("ip_address", UNSET))

        def _parse_os(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        os = _parse_os(d.pop("os", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        def _parse_criticality(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        criticality = _parse_criticality(d.pop("criticality", UNSET))

        def _parse_support_tier(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        support_tier = _parse_support_tier(d.pop("support_tier", UNSET))

        def _parse_tags(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                tags_type_0 = cast(list[str], data)

                return tags_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        tags = _parse_tags(d.pop("tags", UNSET))

        update_ci_request = cls(
            org_id=org_id,
            name=name,
            category=category,
            owner=owner,
            status=status,
            environment=environment,
            location=location,
            ip_address=ip_address,
            os=os,
            version=version,
            criticality=criticality,
            support_tier=support_tier,
            tags=tags,
        )

        update_ci_request.additional_properties = d
        return update_ci_request

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
