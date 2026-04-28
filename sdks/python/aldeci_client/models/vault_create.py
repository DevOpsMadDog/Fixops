from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VaultCreate")


@_attrs_define
class VaultCreate:
    """
    Attributes:
        name (str): Human-readable vault name
        vault_type (str | Unset): hashicorp|aws_secrets|azure_kv|gcp_sm|local Default: 'local'.
        status (str | Unset): active|locked Default: 'active'.
        org_id (str | Unset):  Default: 'default'.
    """

    name: str
    vault_type: str | Unset = "local"
    status: str | Unset = "active"
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        vault_type = self.vault_type

        status = self.status

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if vault_type is not UNSET:
            field_dict["vault_type"] = vault_type
        if status is not UNSET:
            field_dict["status"] = status
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        vault_type = d.pop("vault_type", UNSET)

        status = d.pop("status", UNSET)

        org_id = d.pop("org_id", UNSET)

        vault_create = cls(
            name=name,
            vault_type=vault_type,
            status=status,
            org_id=org_id,
        )

        vault_create.additional_properties = d
        return vault_create

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
