from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.dr_test_result import DRTestResult
from ..models.remediation_status import RemediationStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="DRTestRecord")


@_attrs_define
class DRTestRecord:
    """Record of a DR test exercise.

    Attributes:
        dr_plan_id (str):
        system_name (str):
        test_date (str):
        tested_by (str):
        id (str | Unset):
        result (DRTestResult | Unset):
        actual_rto_minutes (int | None | Unset):
        actual_rpo_minutes (int | None | Unset):
        gaps_found (list[str] | Unset):
        remediation_status (RemediationStatus | Unset):
        remediation_notes (None | str | Unset):
        next_test_due (None | str | Unset):
        evidence_links (list[str] | Unset):
        org_id (str | Unset):  Default: 'default'.
        created_at (str | Unset):
        updated_at (str | Unset):
    """

    dr_plan_id: str
    system_name: str
    test_date: str
    tested_by: str
    id: str | Unset = UNSET
    result: DRTestResult | Unset = UNSET
    actual_rto_minutes: int | None | Unset = UNSET
    actual_rpo_minutes: int | None | Unset = UNSET
    gaps_found: list[str] | Unset = UNSET
    remediation_status: RemediationStatus | Unset = UNSET
    remediation_notes: None | str | Unset = UNSET
    next_test_due: None | str | Unset = UNSET
    evidence_links: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    created_at: str | Unset = UNSET
    updated_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dr_plan_id = self.dr_plan_id

        system_name = self.system_name

        test_date = self.test_date

        tested_by = self.tested_by

        id = self.id

        result: str | Unset = UNSET
        if not isinstance(self.result, Unset):
            result = self.result.value

        actual_rto_minutes: int | None | Unset
        if isinstance(self.actual_rto_minutes, Unset):
            actual_rto_minutes = UNSET
        else:
            actual_rto_minutes = self.actual_rto_minutes

        actual_rpo_minutes: int | None | Unset
        if isinstance(self.actual_rpo_minutes, Unset):
            actual_rpo_minutes = UNSET
        else:
            actual_rpo_minutes = self.actual_rpo_minutes

        gaps_found: list[str] | Unset = UNSET
        if not isinstance(self.gaps_found, Unset):
            gaps_found = self.gaps_found

        remediation_status: str | Unset = UNSET
        if not isinstance(self.remediation_status, Unset):
            remediation_status = self.remediation_status.value

        remediation_notes: None | str | Unset
        if isinstance(self.remediation_notes, Unset):
            remediation_notes = UNSET
        else:
            remediation_notes = self.remediation_notes

        next_test_due: None | str | Unset
        if isinstance(self.next_test_due, Unset):
            next_test_due = UNSET
        else:
            next_test_due = self.next_test_due

        evidence_links: list[str] | Unset = UNSET
        if not isinstance(self.evidence_links, Unset):
            evidence_links = self.evidence_links

        org_id = self.org_id

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "dr_plan_id": dr_plan_id,
                "system_name": system_name,
                "test_date": test_date,
                "tested_by": tested_by,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if result is not UNSET:
            field_dict["result"] = result
        if actual_rto_minutes is not UNSET:
            field_dict["actual_rto_minutes"] = actual_rto_minutes
        if actual_rpo_minutes is not UNSET:
            field_dict["actual_rpo_minutes"] = actual_rpo_minutes
        if gaps_found is not UNSET:
            field_dict["gaps_found"] = gaps_found
        if remediation_status is not UNSET:
            field_dict["remediation_status"] = remediation_status
        if remediation_notes is not UNSET:
            field_dict["remediation_notes"] = remediation_notes
        if next_test_due is not UNSET:
            field_dict["next_test_due"] = next_test_due
        if evidence_links is not UNSET:
            field_dict["evidence_links"] = evidence_links
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        dr_plan_id = d.pop("dr_plan_id")

        system_name = d.pop("system_name")

        test_date = d.pop("test_date")

        tested_by = d.pop("tested_by")

        id = d.pop("id", UNSET)

        _result = d.pop("result", UNSET)
        result: DRTestResult | Unset
        if isinstance(_result, Unset):
            result = UNSET
        else:
            result = DRTestResult(_result)

        def _parse_actual_rto_minutes(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        actual_rto_minutes = _parse_actual_rto_minutes(d.pop("actual_rto_minutes", UNSET))

        def _parse_actual_rpo_minutes(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        actual_rpo_minutes = _parse_actual_rpo_minutes(d.pop("actual_rpo_minutes", UNSET))

        gaps_found = cast(list[str], d.pop("gaps_found", UNSET))

        _remediation_status = d.pop("remediation_status", UNSET)
        remediation_status: RemediationStatus | Unset
        if isinstance(_remediation_status, Unset):
            remediation_status = UNSET
        else:
            remediation_status = RemediationStatus(_remediation_status)

        def _parse_remediation_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation_notes = _parse_remediation_notes(d.pop("remediation_notes", UNSET))

        def _parse_next_test_due(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        next_test_due = _parse_next_test_due(d.pop("next_test_due", UNSET))

        evidence_links = cast(list[str], d.pop("evidence_links", UNSET))

        org_id = d.pop("org_id", UNSET)

        created_at = d.pop("created_at", UNSET)

        updated_at = d.pop("updated_at", UNSET)

        dr_test_record = cls(
            dr_plan_id=dr_plan_id,
            system_name=system_name,
            test_date=test_date,
            tested_by=tested_by,
            id=id,
            result=result,
            actual_rto_minutes=actual_rto_minutes,
            actual_rpo_minutes=actual_rpo_minutes,
            gaps_found=gaps_found,
            remediation_status=remediation_status,
            remediation_notes=remediation_notes,
            next_test_due=next_test_due,
            evidence_links=evidence_links,
            org_id=org_id,
            created_at=created_at,
            updated_at=updated_at,
        )

        dr_test_record.additional_properties = d
        return dr_test_record

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
