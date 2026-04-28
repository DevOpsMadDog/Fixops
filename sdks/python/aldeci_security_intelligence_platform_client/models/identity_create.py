from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IdentityCreate")


@_attrs_define
class IdentityCreate:
    """
    Attributes:
        username (str | Unset):  Default: ''.
        email (str | Unset):  Default: ''.
        identity_type (str | Unset):  Default: 'human'.
        department (str | Unset):  Default: ''.
        risk_score (float | Unset):  Default: 0.0.
        mfa_enabled (bool | Unset):  Default: False.
        last_activity (None | str | Unset):
        status (str | Unset):  Default: 'active'.
    """

    username: str | Unset = ""
    email: str | Unset = ""
    identity_type: str | Unset = "human"
    department: str | Unset = ""
    risk_score: float | Unset = 0.0
    mfa_enabled: bool | Unset = False
    last_activity: None | str | Unset = UNSET
    status: str | Unset = "active"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        username = self.username

        email = self.email

        identity_type = self.identity_type

        department = self.department

        risk_score = self.risk_score

        mfa_enabled = self.mfa_enabled

        last_activity: None | str | Unset
        if isinstance(self.last_activity, Unset):
            last_activity = UNSET
        else:
            last_activity = self.last_activity

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if username is not UNSET:
            field_dict["username"] = username
        if email is not UNSET:
            field_dict["email"] = email
        if identity_type is not UNSET:
            field_dict["identity_type"] = identity_type
        if department is not UNSET:
            field_dict["department"] = department
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if mfa_enabled is not UNSET:
            field_dict["mfa_enabled"] = mfa_enabled
        if last_activity is not UNSET:
            field_dict["last_activity"] = last_activity
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        username = d.pop("username", UNSET)

        email = d.pop("email", UNSET)

        identity_type = d.pop("identity_type", UNSET)

        department = d.pop("department", UNSET)

        risk_score = d.pop("risk_score", UNSET)

        mfa_enabled = d.pop("mfa_enabled", UNSET)

        def _parse_last_activity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_activity = _parse_last_activity(d.pop("last_activity", UNSET))

        status = d.pop("status", UNSET)

        identity_create = cls(
            username=username,
            email=email,
            identity_type=identity_type,
            department=department,
            risk_score=risk_score,
            mfa_enabled=mfa_enabled,
            last_activity=last_activity,
            status=status,
        )

        identity_create.additional_properties = d
        return identity_create

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
