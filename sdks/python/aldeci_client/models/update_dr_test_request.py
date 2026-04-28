from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.dr_test_result import DRTestResult
from ..models.remediation_status import RemediationStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateDRTestRequest")


@_attrs_define
class UpdateDRTestRequest:
    """
    Attributes:
        result (DRTestResult | None | Unset):
        actual_rto_minutes (int | None | Unset):
        actual_rpo_minutes (int | None | Unset):
        gaps_found (list[str] | None | Unset):
        remediation_status (None | RemediationStatus | Unset):
        remediation_notes (None | str | Unset):
        next_test_due (None | str | Unset):
        evidence_links (list[str] | None | Unset):
    """

    result: DRTestResult | None | Unset = UNSET
    actual_rto_minutes: int | None | Unset = UNSET
    actual_rpo_minutes: int | None | Unset = UNSET
    gaps_found: list[str] | None | Unset = UNSET
    remediation_status: None | RemediationStatus | Unset = UNSET
    remediation_notes: None | str | Unset = UNSET
    next_test_due: None | str | Unset = UNSET
    evidence_links: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: None | str | Unset
        if isinstance(self.result, Unset):
            result = UNSET
        elif isinstance(self.result, DRTestResult):
            result = self.result.value
        else:
            result = self.result

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

        gaps_found: list[str] | None | Unset
        if isinstance(self.gaps_found, Unset):
            gaps_found = UNSET
        elif isinstance(self.gaps_found, list):
            gaps_found = self.gaps_found

        else:
            gaps_found = self.gaps_found

        remediation_status: None | str | Unset
        if isinstance(self.remediation_status, Unset):
            remediation_status = UNSET
        elif isinstance(self.remediation_status, RemediationStatus):
            remediation_status = self.remediation_status.value
        else:
            remediation_status = self.remediation_status

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

        evidence_links: list[str] | None | Unset
        if isinstance(self.evidence_links, Unset):
            evidence_links = UNSET
        elif isinstance(self.evidence_links, list):
            evidence_links = self.evidence_links

        else:
            evidence_links = self.evidence_links

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
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

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_result(data: object) -> DRTestResult | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                result_type_0 = DRTestResult(data)

                return result_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DRTestResult | None | Unset, data)

        result = _parse_result(d.pop("result", UNSET))

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

        def _parse_gaps_found(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                gaps_found_type_0 = cast(list[str], data)

                return gaps_found_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        gaps_found = _parse_gaps_found(d.pop("gaps_found", UNSET))

        def _parse_remediation_status(data: object) -> None | RemediationStatus | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                remediation_status_type_0 = RemediationStatus(data)

                return remediation_status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RemediationStatus | Unset, data)

        remediation_status = _parse_remediation_status(d.pop("remediation_status", UNSET))

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

        def _parse_evidence_links(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                evidence_links_type_0 = cast(list[str], data)

                return evidence_links_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        evidence_links = _parse_evidence_links(d.pop("evidence_links", UNSET))

        update_dr_test_request = cls(
            result=result,
            actual_rto_minutes=actual_rto_minutes,
            actual_rpo_minutes=actual_rpo_minutes,
            gaps_found=gaps_found,
            remediation_status=remediation_status,
            remediation_notes=remediation_notes,
            next_test_due=next_test_due,
            evidence_links=evidence_links,
        )

        update_dr_test_request.additional_properties = d
        return update_dr_test_request

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
