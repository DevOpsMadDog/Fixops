from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PolicyIn")


@_attrs_define
class PolicyIn:
    """
    Attributes:
        carrier (str | Unset):  Default: ''.
        policy_number (str | Unset):  Default: ''.
        coverage_type (str | Unset):  Default: 'both'.
        coverage_limit (float | Unset):  Default: 0.0.
        deductible (float | Unset):  Default: 0.0.
        premium_annual (float | Unset):  Default: 0.0.
        effective_date (str | Unset):  Default: ''.
        expiry_date (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'active'.
        covered_events (list[str] | Unset):
    """

    carrier: str | Unset = ""
    policy_number: str | Unset = ""
    coverage_type: str | Unset = "both"
    coverage_limit: float | Unset = 0.0
    deductible: float | Unset = 0.0
    premium_annual: float | Unset = 0.0
    effective_date: str | Unset = ""
    expiry_date: str | Unset = ""
    status: str | Unset = "active"
    covered_events: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        carrier = self.carrier

        policy_number = self.policy_number

        coverage_type = self.coverage_type

        coverage_limit = self.coverage_limit

        deductible = self.deductible

        premium_annual = self.premium_annual

        effective_date = self.effective_date

        expiry_date = self.expiry_date

        status = self.status

        covered_events: list[str] | Unset = UNSET
        if not isinstance(self.covered_events, Unset):
            covered_events = self.covered_events

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if carrier is not UNSET:
            field_dict["carrier"] = carrier
        if policy_number is not UNSET:
            field_dict["policy_number"] = policy_number
        if coverage_type is not UNSET:
            field_dict["coverage_type"] = coverage_type
        if coverage_limit is not UNSET:
            field_dict["coverage_limit"] = coverage_limit
        if deductible is not UNSET:
            field_dict["deductible"] = deductible
        if premium_annual is not UNSET:
            field_dict["premium_annual"] = premium_annual
        if effective_date is not UNSET:
            field_dict["effective_date"] = effective_date
        if expiry_date is not UNSET:
            field_dict["expiry_date"] = expiry_date
        if status is not UNSET:
            field_dict["status"] = status
        if covered_events is not UNSET:
            field_dict["covered_events"] = covered_events

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        carrier = d.pop("carrier", UNSET)

        policy_number = d.pop("policy_number", UNSET)

        coverage_type = d.pop("coverage_type", UNSET)

        coverage_limit = d.pop("coverage_limit", UNSET)

        deductible = d.pop("deductible", UNSET)

        premium_annual = d.pop("premium_annual", UNSET)

        effective_date = d.pop("effective_date", UNSET)

        expiry_date = d.pop("expiry_date", UNSET)

        status = d.pop("status", UNSET)

        covered_events = cast(list[str], d.pop("covered_events", UNSET))

        policy_in = cls(
            carrier=carrier,
            policy_number=policy_number,
            coverage_type=coverage_type,
            coverage_limit=coverage_limit,
            deductible=deductible,
            premium_annual=premium_annual,
            effective_date=effective_date,
            expiry_date=expiry_date,
            status=status,
            covered_events=covered_events,
        )

        policy_in.additional_properties = d
        return policy_in

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
