from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BudgetCreate")


@_attrs_define
class BudgetCreate:
    """
    Attributes:
        budget_name (str):
        org_id (str | Unset):  Default: 'default'.
        account_id (str | Unset):  Default: ''.
        period (str | Unset):  Default: 'monthly'.
        limit_usd (float | Unset):  Default: 0.0.
        current_spend_usd (float | Unset):  Default: 0.0.
        alert_threshold_pct (int | Unset):  Default: 80.
    """

    budget_name: str
    org_id: str | Unset = "default"
    account_id: str | Unset = ""
    period: str | Unset = "monthly"
    limit_usd: float | Unset = 0.0
    current_spend_usd: float | Unset = 0.0
    alert_threshold_pct: int | Unset = 80
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        budget_name = self.budget_name

        org_id = self.org_id

        account_id = self.account_id

        period = self.period

        limit_usd = self.limit_usd

        current_spend_usd = self.current_spend_usd

        alert_threshold_pct = self.alert_threshold_pct

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "budget_name": budget_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if account_id is not UNSET:
            field_dict["account_id"] = account_id
        if period is not UNSET:
            field_dict["period"] = period
        if limit_usd is not UNSET:
            field_dict["limit_usd"] = limit_usd
        if current_spend_usd is not UNSET:
            field_dict["current_spend_usd"] = current_spend_usd
        if alert_threshold_pct is not UNSET:
            field_dict["alert_threshold_pct"] = alert_threshold_pct

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        budget_name = d.pop("budget_name")

        org_id = d.pop("org_id", UNSET)

        account_id = d.pop("account_id", UNSET)

        period = d.pop("period", UNSET)

        limit_usd = d.pop("limit_usd", UNSET)

        current_spend_usd = d.pop("current_spend_usd", UNSET)

        alert_threshold_pct = d.pop("alert_threshold_pct", UNSET)

        budget_create = cls(
            budget_name=budget_name,
            org_id=org_id,
            account_id=account_id,
            period=period,
            limit_usd=limit_usd,
            current_spend_usd=current_spend_usd,
            alert_threshold_pct=alert_threshold_pct,
        )

        budget_create.additional_properties = d
        return budget_create

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
