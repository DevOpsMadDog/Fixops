from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EvaluateAccessRequest")


@_attrs_define
class EvaluateAccessRequest:
    """
    Attributes:
        principal_id (str):
        resource_id (str):
        principal_type (str | Unset):  Default: 'user'.
        resource_type (str | Unset):  Default: 'application'.
        action_requested (str | Unset):  Default: 'read'.
        source_ip (str | Unset):  Default: ''.
        device_trust_score (float | Unset):  Default: 50.0.
        user_trust_score (float | Unset):  Default: 50.0.
        mfa_verified (bool | Unset):  Default: False.
        location (str | Unset):  Default: ''.
        device_type (str | Unset):  Default: ''.
    """

    principal_id: str
    resource_id: str
    principal_type: str | Unset = "user"
    resource_type: str | Unset = "application"
    action_requested: str | Unset = "read"
    source_ip: str | Unset = ""
    device_trust_score: float | Unset = 50.0
    user_trust_score: float | Unset = 50.0
    mfa_verified: bool | Unset = False
    location: str | Unset = ""
    device_type: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        principal_id = self.principal_id

        resource_id = self.resource_id

        principal_type = self.principal_type

        resource_type = self.resource_type

        action_requested = self.action_requested

        source_ip = self.source_ip

        device_trust_score = self.device_trust_score

        user_trust_score = self.user_trust_score

        mfa_verified = self.mfa_verified

        location = self.location

        device_type = self.device_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "principal_id": principal_id,
                "resource_id": resource_id,
            }
        )
        if principal_type is not UNSET:
            field_dict["principal_type"] = principal_type
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if action_requested is not UNSET:
            field_dict["action_requested"] = action_requested
        if source_ip is not UNSET:
            field_dict["source_ip"] = source_ip
        if device_trust_score is not UNSET:
            field_dict["device_trust_score"] = device_trust_score
        if user_trust_score is not UNSET:
            field_dict["user_trust_score"] = user_trust_score
        if mfa_verified is not UNSET:
            field_dict["mfa_verified"] = mfa_verified
        if location is not UNSET:
            field_dict["location"] = location
        if device_type is not UNSET:
            field_dict["device_type"] = device_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        principal_id = d.pop("principal_id")

        resource_id = d.pop("resource_id")

        principal_type = d.pop("principal_type", UNSET)

        resource_type = d.pop("resource_type", UNSET)

        action_requested = d.pop("action_requested", UNSET)

        source_ip = d.pop("source_ip", UNSET)

        device_trust_score = d.pop("device_trust_score", UNSET)

        user_trust_score = d.pop("user_trust_score", UNSET)

        mfa_verified = d.pop("mfa_verified", UNSET)

        location = d.pop("location", UNSET)

        device_type = d.pop("device_type", UNSET)

        evaluate_access_request = cls(
            principal_id=principal_id,
            resource_id=resource_id,
            principal_type=principal_type,
            resource_type=resource_type,
            action_requested=action_requested,
            source_ip=source_ip,
            device_trust_score=device_trust_score,
            user_trust_score=user_trust_score,
            mfa_verified=mfa_verified,
            location=location,
            device_type=device_type,
        )

        evaluate_access_request.additional_properties = d
        return evaluate_access_request

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
