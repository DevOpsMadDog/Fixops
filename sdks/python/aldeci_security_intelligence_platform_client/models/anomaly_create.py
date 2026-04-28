from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AnomalyCreate")


@_attrs_define
class AnomalyCreate:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        account_id (str | Unset):  Default: ''.
        service_name (str | Unset):  Default: ''.
        cost_usd (float | Unset):  Default: 0.0.
        expected_usd (float | Unset):  Default: 0.0.
        deviation_pct (float | Unset):  Default: 0.0.
        anomaly_type (str | Unset):  Default: 'spike'.
        severity (str | Unset):  Default: 'medium'.
    """

    org_id: str | Unset = "default"
    account_id: str | Unset = ""
    service_name: str | Unset = ""
    cost_usd: float | Unset = 0.0
    expected_usd: float | Unset = 0.0
    deviation_pct: float | Unset = 0.0
    anomaly_type: str | Unset = "spike"
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        account_id = self.account_id

        service_name = self.service_name

        cost_usd = self.cost_usd

        expected_usd = self.expected_usd

        deviation_pct = self.deviation_pct

        anomaly_type = self.anomaly_type

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if account_id is not UNSET:
            field_dict["account_id"] = account_id
        if service_name is not UNSET:
            field_dict["service_name"] = service_name
        if cost_usd is not UNSET:
            field_dict["cost_usd"] = cost_usd
        if expected_usd is not UNSET:
            field_dict["expected_usd"] = expected_usd
        if deviation_pct is not UNSET:
            field_dict["deviation_pct"] = deviation_pct
        if anomaly_type is not UNSET:
            field_dict["anomaly_type"] = anomaly_type
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        account_id = d.pop("account_id", UNSET)

        service_name = d.pop("service_name", UNSET)

        cost_usd = d.pop("cost_usd", UNSET)

        expected_usd = d.pop("expected_usd", UNSET)

        deviation_pct = d.pop("deviation_pct", UNSET)

        anomaly_type = d.pop("anomaly_type", UNSET)

        severity = d.pop("severity", UNSET)

        anomaly_create = cls(
            org_id=org_id,
            account_id=account_id,
            service_name=service_name,
            cost_usd=cost_usd,
            expected_usd=expected_usd,
            deviation_pct=deviation_pct,
            anomaly_type=anomaly_type,
            severity=severity,
        )

        anomaly_create.additional_properties = d
        return anomaly_create

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
