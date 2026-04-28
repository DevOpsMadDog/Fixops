from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.dr_test_result import DRTestResult
from ..models.remediation_status import RemediationStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordDRTestRequest")


@_attrs_define
class RecordDRTestRequest:
    """
    Attributes:
        dr_plan_id (str): DR plan that was tested
        system_name (str): System that was tested
        test_date (str): ISO-8601 date of the test
        result (DRTestResult):
        tested_by (str): Person or team who ran the test
        actual_rto_minutes (int | None | Unset):
        actual_rpo_minutes (int | None | Unset):
        gaps_found (list[str] | Unset):
        remediation_status (RemediationStatus | Unset):
        remediation_notes (None | str | Unset):
        next_test_due (None | str | Unset):
        evidence_links (list[str] | Unset):
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    dr_plan_id: str
    system_name: str
    test_date: str
    result: DRTestResult
    tested_by: str
    actual_rto_minutes: int | None | Unset = UNSET
    actual_rpo_minutes: int | None | Unset = UNSET
    gaps_found: list[str] | Unset = UNSET
    remediation_status: RemediationStatus | Unset = UNSET
    remediation_notes: None | str | Unset = UNSET
    next_test_due: None | str | Unset = UNSET
    evidence_links: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dr_plan_id = self.dr_plan_id

        system_name = self.system_name

        test_date = self.test_date

        result = self.result.value

        tested_by = self.tested_by

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

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "dr_plan_id": dr_plan_id,
                "system_name": system_name,
                "test_date": test_date,
                "result": result,
                "tested_by": tested_by,
            }
        )
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

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        dr_plan_id = d.pop("dr_plan_id")

        system_name = d.pop("system_name")

        test_date = d.pop("test_date")

        result = DRTestResult(d.pop("result"))

        tested_by = d.pop("tested_by")

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

        record_dr_test_request = cls(
            dr_plan_id=dr_plan_id,
            system_name=system_name,
            test_date=test_date,
            result=result,
            tested_by=tested_by,
            actual_rto_minutes=actual_rto_minutes,
            actual_rpo_minutes=actual_rpo_minutes,
            gaps_found=gaps_found,
            remediation_status=remediation_status,
            remediation_notes=remediation_notes,
            next_test_due=next_test_due,
            evidence_links=evidence_links,
            org_id=org_id,
        )

        record_dr_test_request.additional_properties = d
        return record_dr_test_request

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
