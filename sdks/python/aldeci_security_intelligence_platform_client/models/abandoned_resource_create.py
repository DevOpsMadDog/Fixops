from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AbandonedResourceCreate")


@_attrs_define
class AbandonedResourceCreate:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        account_id (str | Unset):  Default: ''.
        resource_id (str | Unset):  Default: ''.
        resource_type (str | Unset):  Default: ''.
        resource_name (str | Unset):  Default: ''.
        region (str | Unset):  Default: ''.
        provider (str | Unset):  Default: 'aws'.
        last_used (None | str | Unset):
        monthly_cost_usd (float | Unset):  Default: 0.0.
        security_risk (bool | Unset):  Default: False.
        risk_reason (str | Unset):  Default: ''.
    """

    org_id: str | Unset = "default"
    account_id: str | Unset = ""
    resource_id: str | Unset = ""
    resource_type: str | Unset = ""
    resource_name: str | Unset = ""
    region: str | Unset = ""
    provider: str | Unset = "aws"
    last_used: None | str | Unset = UNSET
    monthly_cost_usd: float | Unset = 0.0
    security_risk: bool | Unset = False
    risk_reason: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        account_id = self.account_id

        resource_id = self.resource_id

        resource_type = self.resource_type

        resource_name = self.resource_name

        region = self.region

        provider = self.provider

        last_used: None | str | Unset
        if isinstance(self.last_used, Unset):
            last_used = UNSET
        else:
            last_used = self.last_used

        monthly_cost_usd = self.monthly_cost_usd

        security_risk = self.security_risk

        risk_reason = self.risk_reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if account_id is not UNSET:
            field_dict["account_id"] = account_id
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if resource_name is not UNSET:
            field_dict["resource_name"] = resource_name
        if region is not UNSET:
            field_dict["region"] = region
        if provider is not UNSET:
            field_dict["provider"] = provider
        if last_used is not UNSET:
            field_dict["last_used"] = last_used
        if monthly_cost_usd is not UNSET:
            field_dict["monthly_cost_usd"] = monthly_cost_usd
        if security_risk is not UNSET:
            field_dict["security_risk"] = security_risk
        if risk_reason is not UNSET:
            field_dict["risk_reason"] = risk_reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        account_id = d.pop("account_id", UNSET)

        resource_id = d.pop("resource_id", UNSET)

        resource_type = d.pop("resource_type", UNSET)

        resource_name = d.pop("resource_name", UNSET)

        region = d.pop("region", UNSET)

        provider = d.pop("provider", UNSET)

        def _parse_last_used(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_used = _parse_last_used(d.pop("last_used", UNSET))

        monthly_cost_usd = d.pop("monthly_cost_usd", UNSET)

        security_risk = d.pop("security_risk", UNSET)

        risk_reason = d.pop("risk_reason", UNSET)

        abandoned_resource_create = cls(
            org_id=org_id,
            account_id=account_id,
            resource_id=resource_id,
            resource_type=resource_type,
            resource_name=resource_name,
            region=region,
            provider=provider,
            last_used=last_used,
            monthly_cost_usd=monthly_cost_usd,
            security_risk=security_risk,
            risk_reason=risk_reason,
        )

        abandoned_resource_create.additional_properties = d
        return abandoned_resource_create

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
