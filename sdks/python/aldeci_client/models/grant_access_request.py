from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GrantAccessRequest")


@_attrs_define
class GrantAccessRequest:
    """
    Attributes:
        subject_id (str): User or group receiving access
        resource_id (str): Resource being accessed
        policy_id (str): Policy governing this grant
        granted_by (str): User granting access
        expires_at (None | str | Unset): ISO expiry timestamp (optional)
    """

    subject_id: str
    resource_id: str
    policy_id: str
    granted_by: str
    expires_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        subject_id = self.subject_id

        resource_id = self.resource_id

        policy_id = self.policy_id

        granted_by = self.granted_by

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "subject_id": subject_id,
                "resource_id": resource_id,
                "policy_id": policy_id,
                "granted_by": granted_by,
            }
        )
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        subject_id = d.pop("subject_id")

        resource_id = d.pop("resource_id")

        policy_id = d.pop("policy_id")

        granted_by = d.pop("granted_by")

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        grant_access_request = cls(
            subject_id=subject_id,
            resource_id=resource_id,
            policy_id=policy_id,
            granted_by=granted_by,
            expires_at=expires_at,
        )

        grant_access_request.additional_properties = d
        return grant_access_request

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
