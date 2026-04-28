from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BCScore")


@_attrs_define
class BCScore:
    """Business continuity readiness score for an org.

    Attributes:
        org_id (str):
        score (float | Unset):  Default: 0.0.
        grade (str | Unset):  Default: 'F'.
        backup_coverage_pct (float | Unset):  Default: 0.0.
        test_frequency_score (float | Unset):  Default: 0.0.
        rpo_compliance_pct (float | Unset):  Default: 0.0.
        rto_compliance_pct (float | Unset):  Default: 0.0.
        encryption_coverage_pct (float | Unset):  Default: 0.0.
        geo_redundancy_pct (float | Unset):  Default: 0.0.
        verification_pass_rate (float | Unset):  Default: 0.0.
        open_gaps (int | Unset):  Default: 0.
        systems_without_backup (list[str] | Unset):
        systems_without_dr_plan (list[str] | Unset):
        computed_at (str | Unset):
    """

    org_id: str
    score: float | Unset = 0.0
    grade: str | Unset = "F"
    backup_coverage_pct: float | Unset = 0.0
    test_frequency_score: float | Unset = 0.0
    rpo_compliance_pct: float | Unset = 0.0
    rto_compliance_pct: float | Unset = 0.0
    encryption_coverage_pct: float | Unset = 0.0
    geo_redundancy_pct: float | Unset = 0.0
    verification_pass_rate: float | Unset = 0.0
    open_gaps: int | Unset = 0
    systems_without_backup: list[str] | Unset = UNSET
    systems_without_dr_plan: list[str] | Unset = UNSET
    computed_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        score = self.score

        grade = self.grade

        backup_coverage_pct = self.backup_coverage_pct

        test_frequency_score = self.test_frequency_score

        rpo_compliance_pct = self.rpo_compliance_pct

        rto_compliance_pct = self.rto_compliance_pct

        encryption_coverage_pct = self.encryption_coverage_pct

        geo_redundancy_pct = self.geo_redundancy_pct

        verification_pass_rate = self.verification_pass_rate

        open_gaps = self.open_gaps

        systems_without_backup: list[str] | Unset = UNSET
        if not isinstance(self.systems_without_backup, Unset):
            systems_without_backup = self.systems_without_backup

        systems_without_dr_plan: list[str] | Unset = UNSET
        if not isinstance(self.systems_without_dr_plan, Unset):
            systems_without_dr_plan = self.systems_without_dr_plan

        computed_at = self.computed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if score is not UNSET:
            field_dict["score"] = score
        if grade is not UNSET:
            field_dict["grade"] = grade
        if backup_coverage_pct is not UNSET:
            field_dict["backup_coverage_pct"] = backup_coverage_pct
        if test_frequency_score is not UNSET:
            field_dict["test_frequency_score"] = test_frequency_score
        if rpo_compliance_pct is not UNSET:
            field_dict["rpo_compliance_pct"] = rpo_compliance_pct
        if rto_compliance_pct is not UNSET:
            field_dict["rto_compliance_pct"] = rto_compliance_pct
        if encryption_coverage_pct is not UNSET:
            field_dict["encryption_coverage_pct"] = encryption_coverage_pct
        if geo_redundancy_pct is not UNSET:
            field_dict["geo_redundancy_pct"] = geo_redundancy_pct
        if verification_pass_rate is not UNSET:
            field_dict["verification_pass_rate"] = verification_pass_rate
        if open_gaps is not UNSET:
            field_dict["open_gaps"] = open_gaps
        if systems_without_backup is not UNSET:
            field_dict["systems_without_backup"] = systems_without_backup
        if systems_without_dr_plan is not UNSET:
            field_dict["systems_without_dr_plan"] = systems_without_dr_plan
        if computed_at is not UNSET:
            field_dict["computed_at"] = computed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        score = d.pop("score", UNSET)

        grade = d.pop("grade", UNSET)

        backup_coverage_pct = d.pop("backup_coverage_pct", UNSET)

        test_frequency_score = d.pop("test_frequency_score", UNSET)

        rpo_compliance_pct = d.pop("rpo_compliance_pct", UNSET)

        rto_compliance_pct = d.pop("rto_compliance_pct", UNSET)

        encryption_coverage_pct = d.pop("encryption_coverage_pct", UNSET)

        geo_redundancy_pct = d.pop("geo_redundancy_pct", UNSET)

        verification_pass_rate = d.pop("verification_pass_rate", UNSET)

        open_gaps = d.pop("open_gaps", UNSET)

        systems_without_backup = cast(list[str], d.pop("systems_without_backup", UNSET))

        systems_without_dr_plan = cast(list[str], d.pop("systems_without_dr_plan", UNSET))

        computed_at = d.pop("computed_at", UNSET)

        bc_score = cls(
            org_id=org_id,
            score=score,
            grade=grade,
            backup_coverage_pct=backup_coverage_pct,
            test_frequency_score=test_frequency_score,
            rpo_compliance_pct=rpo_compliance_pct,
            rto_compliance_pct=rto_compliance_pct,
            encryption_coverage_pct=encryption_coverage_pct,
            geo_redundancy_pct=geo_redundancy_pct,
            verification_pass_rate=verification_pass_rate,
            open_gaps=open_gaps,
            systems_without_backup=systems_without_backup,
            systems_without_dr_plan=systems_without_dr_plan,
            computed_at=computed_at,
        )

        bc_score.additional_properties = d
        return bc_score

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
