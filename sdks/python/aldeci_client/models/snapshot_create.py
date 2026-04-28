from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SnapshotCreate")


@_attrs_define
class SnapshotCreate:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        account_id (str | Unset):  Default: ''.
        provider (str | Unset):  Default: 'aws'.
        service_name (str | Unset):  Default: ''.
        region (str | Unset):  Default: ''.
        cost_usd (float | Unset):  Default: 0.0.
        previous_cost_usd (float | Unset):  Default: 0.0.
        change_pct (float | Unset):  Default: 0.0.
        snapshot_date (str | Unset):  Default: ''.
        last_used (None | str | Unset):
        has_public_ip (bool | Unset):  Default: False.
        is_idle (bool | Unset):  Default: False.
    """

    org_id: str | Unset = "default"
    account_id: str | Unset = ""
    provider: str | Unset = "aws"
    service_name: str | Unset = ""
    region: str | Unset = ""
    cost_usd: float | Unset = 0.0
    previous_cost_usd: float | Unset = 0.0
    change_pct: float | Unset = 0.0
    snapshot_date: str | Unset = ""
    last_used: None | str | Unset = UNSET
    has_public_ip: bool | Unset = False
    is_idle: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        account_id = self.account_id

        provider = self.provider

        service_name = self.service_name

        region = self.region

        cost_usd = self.cost_usd

        previous_cost_usd = self.previous_cost_usd

        change_pct = self.change_pct

        snapshot_date = self.snapshot_date

        last_used: None | str | Unset
        if isinstance(self.last_used, Unset):
            last_used = UNSET
        else:
            last_used = self.last_used

        has_public_ip = self.has_public_ip

        is_idle = self.is_idle

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if account_id is not UNSET:
            field_dict["account_id"] = account_id
        if provider is not UNSET:
            field_dict["provider"] = provider
        if service_name is not UNSET:
            field_dict["service_name"] = service_name
        if region is not UNSET:
            field_dict["region"] = region
        if cost_usd is not UNSET:
            field_dict["cost_usd"] = cost_usd
        if previous_cost_usd is not UNSET:
            field_dict["previous_cost_usd"] = previous_cost_usd
        if change_pct is not UNSET:
            field_dict["change_pct"] = change_pct
        if snapshot_date is not UNSET:
            field_dict["snapshot_date"] = snapshot_date
        if last_used is not UNSET:
            field_dict["last_used"] = last_used
        if has_public_ip is not UNSET:
            field_dict["has_public_ip"] = has_public_ip
        if is_idle is not UNSET:
            field_dict["is_idle"] = is_idle

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        account_id = d.pop("account_id", UNSET)

        provider = d.pop("provider", UNSET)

        service_name = d.pop("service_name", UNSET)

        region = d.pop("region", UNSET)

        cost_usd = d.pop("cost_usd", UNSET)

        previous_cost_usd = d.pop("previous_cost_usd", UNSET)

        change_pct = d.pop("change_pct", UNSET)

        snapshot_date = d.pop("snapshot_date", UNSET)

        def _parse_last_used(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_used = _parse_last_used(d.pop("last_used", UNSET))

        has_public_ip = d.pop("has_public_ip", UNSET)

        is_idle = d.pop("is_idle", UNSET)

        snapshot_create = cls(
            org_id=org_id,
            account_id=account_id,
            provider=provider,
            service_name=service_name,
            region=region,
            cost_usd=cost_usd,
            previous_cost_usd=previous_cost_usd,
            change_pct=change_pct,
            snapshot_date=snapshot_date,
            last_used=last_used,
            has_public_ip=has_public_ip,
            is_idle=is_idle,
        )

        snapshot_create.additional_properties = d
        return snapshot_create

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
