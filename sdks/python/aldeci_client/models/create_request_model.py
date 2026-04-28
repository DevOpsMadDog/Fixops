from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateRequestModel")


@_attrs_define
class CreateRequestModel:
    """
    Attributes:
        policy_name (str):
        exception_type (str | Unset):  Default: 'policy-waiver'.
        requestor (str | Unset):  Default: ''.
        business_justification (str | Unset):  Default: ''.
        risk_description (str | Unset):  Default: ''.
        compensating_controls (str | Unset):  Default: ''.
        priority (str | Unset):  Default: 'medium'.
        expires_at (None | str | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    policy_name: str
    exception_type: str | Unset = "policy-waiver"
    requestor: str | Unset = ""
    business_justification: str | Unset = ""
    risk_description: str | Unset = ""
    compensating_controls: str | Unset = ""
    priority: str | Unset = "medium"
    expires_at: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_name = self.policy_name

        exception_type = self.exception_type

        requestor = self.requestor

        business_justification = self.business_justification

        risk_description = self.risk_description

        compensating_controls = self.compensating_controls

        priority = self.priority

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_name": policy_name,
            }
        )
        if exception_type is not UNSET:
            field_dict["exception_type"] = exception_type
        if requestor is not UNSET:
            field_dict["requestor"] = requestor
        if business_justification is not UNSET:
            field_dict["business_justification"] = business_justification
        if risk_description is not UNSET:
            field_dict["risk_description"] = risk_description
        if compensating_controls is not UNSET:
            field_dict["compensating_controls"] = compensating_controls
        if priority is not UNSET:
            field_dict["priority"] = priority
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        policy_name = d.pop("policy_name")

        exception_type = d.pop("exception_type", UNSET)

        requestor = d.pop("requestor", UNSET)

        business_justification = d.pop("business_justification", UNSET)

        risk_description = d.pop("risk_description", UNSET)

        compensating_controls = d.pop("compensating_controls", UNSET)

        priority = d.pop("priority", UNSET)

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        org_id = d.pop("org_id", UNSET)

        create_request_model = cls(
            policy_name=policy_name,
            exception_type=exception_type,
            requestor=requestor,
            business_justification=business_justification,
            risk_description=risk_description,
            compensating_controls=compensating_controls,
            priority=priority,
            expires_at=expires_at,
            org_id=org_id,
        )

        create_request_model.additional_properties = d
        return create_request_model

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
