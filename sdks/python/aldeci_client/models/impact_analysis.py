from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ImpactAnalysis")


@_attrs_define
class ImpactAnalysis:
    """Impact analysis for a change.

    Attributes:
        affected_services (list[str] | Unset):
        affected_data_stores (list[str] | Unset):
        affected_compliance_frameworks (list[str] | Unset):
        blast_radius_score (float | Unset): 0-10 score: how widely this change propagates Default: 0.0.
        security_impact (bool | Unset): Change has security implications Default: False.
        data_migration_required (bool | Unset): Change requires data migration Default: False.
        production_impact (bool | Unset): Change affects production environment Default: True.
        estimated_downtime_minutes (int | Unset):  Default: 0.
        user_impact_count (int | Unset): Estimated number of affected users Default: 0.
        dependency_changes (list[str] | Unset): Linked code or service dependencies
        risk_score (float | Unset): Computed composite risk score 0-100 Default: 0.0.
    """

    affected_services: list[str] | Unset = UNSET
    affected_data_stores: list[str] | Unset = UNSET
    affected_compliance_frameworks: list[str] | Unset = UNSET
    blast_radius_score: float | Unset = 0.0
    security_impact: bool | Unset = False
    data_migration_required: bool | Unset = False
    production_impact: bool | Unset = True
    estimated_downtime_minutes: int | Unset = 0
    user_impact_count: int | Unset = 0
    dependency_changes: list[str] | Unset = UNSET
    risk_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        affected_services: list[str] | Unset = UNSET
        if not isinstance(self.affected_services, Unset):
            affected_services = self.affected_services

        affected_data_stores: list[str] | Unset = UNSET
        if not isinstance(self.affected_data_stores, Unset):
            affected_data_stores = self.affected_data_stores

        affected_compliance_frameworks: list[str] | Unset = UNSET
        if not isinstance(self.affected_compliance_frameworks, Unset):
            affected_compliance_frameworks = self.affected_compliance_frameworks

        blast_radius_score = self.blast_radius_score

        security_impact = self.security_impact

        data_migration_required = self.data_migration_required

        production_impact = self.production_impact

        estimated_downtime_minutes = self.estimated_downtime_minutes

        user_impact_count = self.user_impact_count

        dependency_changes: list[str] | Unset = UNSET
        if not isinstance(self.dependency_changes, Unset):
            dependency_changes = self.dependency_changes

        risk_score = self.risk_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if affected_services is not UNSET:
            field_dict["affected_services"] = affected_services
        if affected_data_stores is not UNSET:
            field_dict["affected_data_stores"] = affected_data_stores
        if affected_compliance_frameworks is not UNSET:
            field_dict["affected_compliance_frameworks"] = affected_compliance_frameworks
        if blast_radius_score is not UNSET:
            field_dict["blast_radius_score"] = blast_radius_score
        if security_impact is not UNSET:
            field_dict["security_impact"] = security_impact
        if data_migration_required is not UNSET:
            field_dict["data_migration_required"] = data_migration_required
        if production_impact is not UNSET:
            field_dict["production_impact"] = production_impact
        if estimated_downtime_minutes is not UNSET:
            field_dict["estimated_downtime_minutes"] = estimated_downtime_minutes
        if user_impact_count is not UNSET:
            field_dict["user_impact_count"] = user_impact_count
        if dependency_changes is not UNSET:
            field_dict["dependency_changes"] = dependency_changes
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        affected_services = cast(list[str], d.pop("affected_services", UNSET))

        affected_data_stores = cast(list[str], d.pop("affected_data_stores", UNSET))

        affected_compliance_frameworks = cast(list[str], d.pop("affected_compliance_frameworks", UNSET))

        blast_radius_score = d.pop("blast_radius_score", UNSET)

        security_impact = d.pop("security_impact", UNSET)

        data_migration_required = d.pop("data_migration_required", UNSET)

        production_impact = d.pop("production_impact", UNSET)

        estimated_downtime_minutes = d.pop("estimated_downtime_minutes", UNSET)

        user_impact_count = d.pop("user_impact_count", UNSET)

        dependency_changes = cast(list[str], d.pop("dependency_changes", UNSET))

        risk_score = d.pop("risk_score", UNSET)

        impact_analysis = cls(
            affected_services=affected_services,
            affected_data_stores=affected_data_stores,
            affected_compliance_frameworks=affected_compliance_frameworks,
            blast_radius_score=blast_radius_score,
            security_impact=security_impact,
            data_migration_required=data_migration_required,
            production_impact=production_impact,
            estimated_downtime_minutes=estimated_downtime_minutes,
            user_impact_count=user_impact_count,
            dependency_changes=dependency_changes,
            risk_score=risk_score,
        )

        impact_analysis.additional_properties = d
        return impact_analysis

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
