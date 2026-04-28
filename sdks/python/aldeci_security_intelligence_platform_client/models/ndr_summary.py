from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="NDRSummary")


@_attrs_define
class NDRSummary:
    """
    Attributes:
        org_id (str):
        total_assets (int):
        segmentation_violations (int):
        firewall_issues (int):
        dns_threats (int):
        tls_issues (int):
        flow_anomalies (int):
        zero_trust_score (float | None):
        computed_at (datetime.datetime | Unset):
    """

    org_id: str
    total_assets: int
    segmentation_violations: int
    firewall_issues: int
    dns_threats: int
    tls_issues: int
    flow_anomalies: int
    zero_trust_score: float | None
    computed_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total_assets = self.total_assets

        segmentation_violations = self.segmentation_violations

        firewall_issues = self.firewall_issues

        dns_threats = self.dns_threats

        tls_issues = self.tls_issues

        flow_anomalies = self.flow_anomalies

        zero_trust_score: float | None
        zero_trust_score = self.zero_trust_score

        computed_at: str | Unset = UNSET
        if not isinstance(self.computed_at, Unset):
            computed_at = self.computed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total_assets": total_assets,
                "segmentation_violations": segmentation_violations,
                "firewall_issues": firewall_issues,
                "dns_threats": dns_threats,
                "tls_issues": tls_issues,
                "flow_anomalies": flow_anomalies,
                "zero_trust_score": zero_trust_score,
            }
        )
        if computed_at is not UNSET:
            field_dict["computed_at"] = computed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        total_assets = d.pop("total_assets")

        segmentation_violations = d.pop("segmentation_violations")

        firewall_issues = d.pop("firewall_issues")

        dns_threats = d.pop("dns_threats")

        tls_issues = d.pop("tls_issues")

        flow_anomalies = d.pop("flow_anomalies")

        def _parse_zero_trust_score(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        zero_trust_score = _parse_zero_trust_score(d.pop("zero_trust_score"))

        _computed_at = d.pop("computed_at", UNSET)
        computed_at: datetime.datetime | Unset
        if isinstance(_computed_at, Unset):
            computed_at = UNSET
        else:
            computed_at = isoparse(_computed_at)

        ndr_summary = cls(
            org_id=org_id,
            total_assets=total_assets,
            segmentation_violations=segmentation_violations,
            firewall_issues=firewall_issues,
            dns_threats=dns_threats,
            tls_issues=tls_issues,
            flow_anomalies=flow_anomalies,
            zero_trust_score=zero_trust_score,
            computed_at=computed_at,
        )

        ndr_summary.additional_properties = d
        return ndr_summary

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
