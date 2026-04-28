from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SecretCreate")


@_attrs_define
class SecretCreate:
    """
    Attributes:
        name (str): Secret name / identifier
        secret_type (str | Unset): api_key|db_password|tls_cert|oauth_token|ssh_key|service_account Default: 'api_key'.
        owner (str | Unset): Owner team or user Default: ''.
        environment (str | Unset): prod|staging|dev Default: 'prod'.
        rotation_days (int | Unset): Days between required rotations Default: 90.
        expires_at (float | None | Unset): Unix timestamp of expiry (computed if omitted)
        last_rotated (float | None | Unset): Unix timestamp of last rotation
        org_id (str | Unset):  Default: 'default'.
    """

    name: str
    secret_type: str | Unset = "api_key"
    owner: str | Unset = ""
    environment: str | Unset = "prod"
    rotation_days: int | Unset = 90
    expires_at: float | None | Unset = UNSET
    last_rotated: float | None | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        secret_type = self.secret_type

        owner = self.owner

        environment = self.environment

        rotation_days = self.rotation_days

        expires_at: float | None | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        last_rotated: float | None | Unset
        if isinstance(self.last_rotated, Unset):
            last_rotated = UNSET
        else:
            last_rotated = self.last_rotated

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if secret_type is not UNSET:
            field_dict["secret_type"] = secret_type
        if owner is not UNSET:
            field_dict["owner"] = owner
        if environment is not UNSET:
            field_dict["environment"] = environment
        if rotation_days is not UNSET:
            field_dict["rotation_days"] = rotation_days
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if last_rotated is not UNSET:
            field_dict["last_rotated"] = last_rotated
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        secret_type = d.pop("secret_type", UNSET)

        owner = d.pop("owner", UNSET)

        environment = d.pop("environment", UNSET)

        rotation_days = d.pop("rotation_days", UNSET)

        def _parse_expires_at(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        def _parse_last_rotated(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        last_rotated = _parse_last_rotated(d.pop("last_rotated", UNSET))

        org_id = d.pop("org_id", UNSET)

        secret_create = cls(
            name=name,
            secret_type=secret_type,
            owner=owner,
            environment=environment,
            rotation_days=rotation_days,
            expires_at=expires_at,
            last_rotated=last_rotated,
            org_id=org_id,
        )

        secret_create.additional_properties = d
        return secret_create

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
