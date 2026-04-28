from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateCorrelationIn")


@_attrs_define
class CreateCorrelationIn:
    """
    Attributes:
        primary_cve (str): Primary CVE identifier
        related_cves (list[str] | Unset): Related CVE IDs
        asset_ids (list[str] | Unset): Affected asset IDs
        correlation_type (str | Unset): attack_chain|shared_component|same_vendor|exploit_similarity|environmental
            Default: 'shared_component'.
        risk_multiplier (float | Unset): Risk multiplier clamped 0.1-10.0 Default: 1.0.
        combined_risk_score (float | Unset): Combined risk score Default: 0.0.
        severity (str | Unset): critical|high|medium|low Default: 'medium'.
    """

    primary_cve: str
    related_cves: list[str] | Unset = UNSET
    asset_ids: list[str] | Unset = UNSET
    correlation_type: str | Unset = "shared_component"
    risk_multiplier: float | Unset = 1.0
    combined_risk_score: float | Unset = 0.0
    severity: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        primary_cve = self.primary_cve

        related_cves: list[str] | Unset = UNSET
        if not isinstance(self.related_cves, Unset):
            related_cves = self.related_cves

        asset_ids: list[str] | Unset = UNSET
        if not isinstance(self.asset_ids, Unset):
            asset_ids = self.asset_ids

        correlation_type = self.correlation_type

        risk_multiplier = self.risk_multiplier

        combined_risk_score = self.combined_risk_score

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "primary_cve": primary_cve,
            }
        )
        if related_cves is not UNSET:
            field_dict["related_cves"] = related_cves
        if asset_ids is not UNSET:
            field_dict["asset_ids"] = asset_ids
        if correlation_type is not UNSET:
            field_dict["correlation_type"] = correlation_type
        if risk_multiplier is not UNSET:
            field_dict["risk_multiplier"] = risk_multiplier
        if combined_risk_score is not UNSET:
            field_dict["combined_risk_score"] = combined_risk_score
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        primary_cve = d.pop("primary_cve")

        related_cves = cast(list[str], d.pop("related_cves", UNSET))

        asset_ids = cast(list[str], d.pop("asset_ids", UNSET))

        correlation_type = d.pop("correlation_type", UNSET)

        risk_multiplier = d.pop("risk_multiplier", UNSET)

        combined_risk_score = d.pop("combined_risk_score", UNSET)

        severity = d.pop("severity", UNSET)

        create_correlation_in = cls(
            primary_cve=primary_cve,
            related_cves=related_cves,
            asset_ids=asset_ids,
            correlation_type=correlation_type,
            risk_multiplier=risk_multiplier,
            combined_risk_score=combined_risk_score,
            severity=severity,
        )

        create_correlation_in.additional_properties = d
        return create_correlation_in

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
