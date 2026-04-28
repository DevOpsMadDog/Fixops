from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterIdentityRequest")


@_attrs_define
class RegisterIdentityRequest:
    """
    Attributes:
        identity_name (str):
        org_id (str | Unset):  Default: 'default'.
        identity_type (str | Unset):  Default: 'user'.
        cloud_provider (str | Unset):  Default: 'aws'.
        account_id (str | Unset):  Default: ''.
        permissions (list[str] | Unset):
        privilege_level (str | Unset):  Default: 'none'.
        is_federated (bool | Unset):  Default: False.
        mfa_enabled (bool | Unset):  Default: False.
        last_activity (None | str | Unset):
    """

    identity_name: str
    org_id: str | Unset = "default"
    identity_type: str | Unset = "user"
    cloud_provider: str | Unset = "aws"
    account_id: str | Unset = ""
    permissions: list[str] | Unset = UNSET
    privilege_level: str | Unset = "none"
    is_federated: bool | Unset = False
    mfa_enabled: bool | Unset = False
    last_activity: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        identity_name = self.identity_name

        org_id = self.org_id

        identity_type = self.identity_type

        cloud_provider = self.cloud_provider

        account_id = self.account_id

        permissions: list[str] | Unset = UNSET
        if not isinstance(self.permissions, Unset):
            permissions = self.permissions

        privilege_level = self.privilege_level

        is_federated = self.is_federated

        mfa_enabled = self.mfa_enabled

        last_activity: None | str | Unset
        if isinstance(self.last_activity, Unset):
            last_activity = UNSET
        else:
            last_activity = self.last_activity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "identity_name": identity_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if identity_type is not UNSET:
            field_dict["identity_type"] = identity_type
        if cloud_provider is not UNSET:
            field_dict["cloud_provider"] = cloud_provider
        if account_id is not UNSET:
            field_dict["account_id"] = account_id
        if permissions is not UNSET:
            field_dict["permissions"] = permissions
        if privilege_level is not UNSET:
            field_dict["privilege_level"] = privilege_level
        if is_federated is not UNSET:
            field_dict["is_federated"] = is_federated
        if mfa_enabled is not UNSET:
            field_dict["mfa_enabled"] = mfa_enabled
        if last_activity is not UNSET:
            field_dict["last_activity"] = last_activity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        identity_name = d.pop("identity_name")

        org_id = d.pop("org_id", UNSET)

        identity_type = d.pop("identity_type", UNSET)

        cloud_provider = d.pop("cloud_provider", UNSET)

        account_id = d.pop("account_id", UNSET)

        permissions = cast(list[str], d.pop("permissions", UNSET))

        privilege_level = d.pop("privilege_level", UNSET)

        is_federated = d.pop("is_federated", UNSET)

        mfa_enabled = d.pop("mfa_enabled", UNSET)

        def _parse_last_activity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_activity = _parse_last_activity(d.pop("last_activity", UNSET))

        register_identity_request = cls(
            identity_name=identity_name,
            org_id=org_id,
            identity_type=identity_type,
            cloud_provider=cloud_provider,
            account_id=account_id,
            permissions=permissions,
            privilege_level=privilege_level,
            is_federated=is_federated,
            mfa_enabled=mfa_enabled,
            last_activity=last_activity,
        )

        register_identity_request.additional_properties = d
        return register_identity_request

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
