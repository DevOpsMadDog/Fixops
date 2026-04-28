from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AccountIn")


@_attrs_define
class AccountIn:
    """
    Attributes:
        account_id (str):
        account_name (str | Unset):  Default: ''.
        provider (str | Unset):  Default: 'aws'.
        region (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'healthy'.
        resource_count (int | Unset):  Default: 0.
        finding_count (int | Unset):  Default: 0.
        risk_score (float | Unset):  Default: 0.0.
        last_scanned (None | str | Unset):
    """

    account_id: str
    account_name: str | Unset = ""
    provider: str | Unset = "aws"
    region: str | Unset = ""
    status: str | Unset = "healthy"
    resource_count: int | Unset = 0
    finding_count: int | Unset = 0
    risk_score: float | Unset = 0.0
    last_scanned: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        account_id = self.account_id

        account_name = self.account_name

        provider = self.provider

        region = self.region

        status = self.status

        resource_count = self.resource_count

        finding_count = self.finding_count

        risk_score = self.risk_score

        last_scanned: None | str | Unset
        if isinstance(self.last_scanned, Unset):
            last_scanned = UNSET
        else:
            last_scanned = self.last_scanned

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "account_id": account_id,
            }
        )
        if account_name is not UNSET:
            field_dict["account_name"] = account_name
        if provider is not UNSET:
            field_dict["provider"] = provider
        if region is not UNSET:
            field_dict["region"] = region
        if status is not UNSET:
            field_dict["status"] = status
        if resource_count is not UNSET:
            field_dict["resource_count"] = resource_count
        if finding_count is not UNSET:
            field_dict["finding_count"] = finding_count
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if last_scanned is not UNSET:
            field_dict["last_scanned"] = last_scanned

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        account_id = d.pop("account_id")

        account_name = d.pop("account_name", UNSET)

        provider = d.pop("provider", UNSET)

        region = d.pop("region", UNSET)

        status = d.pop("status", UNSET)

        resource_count = d.pop("resource_count", UNSET)

        finding_count = d.pop("finding_count", UNSET)

        risk_score = d.pop("risk_score", UNSET)

        def _parse_last_scanned(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_scanned = _parse_last_scanned(d.pop("last_scanned", UNSET))

        account_in = cls(
            account_id=account_id,
            account_name=account_name,
            provider=provider,
            region=region,
            status=status,
            resource_count=resource_count,
            finding_count=finding_count,
            risk_score=risk_score,
            last_scanned=last_scanned,
        )

        account_in.additional_properties = d
        return account_in

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
