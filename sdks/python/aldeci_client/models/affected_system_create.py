from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AffectedSystemCreate")


@_attrs_define
class AffectedSystemCreate:
    """
    Attributes:
        hostname (str | Unset):  Default: ''.
        ip_address (str | Unset):  Default: ''.
        system_type (str | Unset):  Default: ''.
        affected_at (None | str | Unset):
        restored_at (None | str | Unset):
        impact_description (str | Unset):  Default: ''.
    """

    hostname: str | Unset = ""
    ip_address: str | Unset = ""
    system_type: str | Unset = ""
    affected_at: None | str | Unset = UNSET
    restored_at: None | str | Unset = UNSET
    impact_description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hostname = self.hostname

        ip_address = self.ip_address

        system_type = self.system_type

        affected_at: None | str | Unset
        if isinstance(self.affected_at, Unset):
            affected_at = UNSET
        else:
            affected_at = self.affected_at

        restored_at: None | str | Unset
        if isinstance(self.restored_at, Unset):
            restored_at = UNSET
        else:
            restored_at = self.restored_at

        impact_description = self.impact_description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if hostname is not UNSET:
            field_dict["hostname"] = hostname
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if system_type is not UNSET:
            field_dict["system_type"] = system_type
        if affected_at is not UNSET:
            field_dict["affected_at"] = affected_at
        if restored_at is not UNSET:
            field_dict["restored_at"] = restored_at
        if impact_description is not UNSET:
            field_dict["impact_description"] = impact_description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        hostname = d.pop("hostname", UNSET)

        ip_address = d.pop("ip_address", UNSET)

        system_type = d.pop("system_type", UNSET)

        def _parse_affected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        affected_at = _parse_affected_at(d.pop("affected_at", UNSET))

        def _parse_restored_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        restored_at = _parse_restored_at(d.pop("restored_at", UNSET))

        impact_description = d.pop("impact_description", UNSET)

        affected_system_create = cls(
            hostname=hostname,
            ip_address=ip_address,
            system_type=system_type,
            affected_at=affected_at,
            restored_at=restored_at,
            impact_description=impact_description,
        )

        affected_system_create.additional_properties = d
        return affected_system_create

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
