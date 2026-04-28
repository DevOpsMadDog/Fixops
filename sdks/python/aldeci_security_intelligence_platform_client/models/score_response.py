from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.score_response_findings_by_severity_type_0 import ScoreResponseFindingsBySeverityType0


T = TypeVar("T", bound="ScoreResponse")


@_attrs_define
class ScoreResponse:
    """Security score summary for ALDECI itself.

    Attributes:
        scan_id (None | str | Unset):
        score (float | None | Unset):
        grade (None | str | Unset):
        scanned_at (None | str | Unset):
        total_findings (int | None | Unset):
        findings_by_severity (None | ScoreResponseFindingsBySeverityType0 | Unset):
        top_priorities (list[str] | None | Unset):
        message (None | str | Unset):
    """

    scan_id: None | str | Unset = UNSET
    score: float | None | Unset = UNSET
    grade: None | str | Unset = UNSET
    scanned_at: None | str | Unset = UNSET
    total_findings: int | None | Unset = UNSET
    findings_by_severity: None | ScoreResponseFindingsBySeverityType0 | Unset = UNSET
    top_priorities: list[str] | None | Unset = UNSET
    message: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.score_response_findings_by_severity_type_0 import ScoreResponseFindingsBySeverityType0

        scan_id: None | str | Unset
        if isinstance(self.scan_id, Unset):
            scan_id = UNSET
        else:
            scan_id = self.scan_id

        score: float | None | Unset
        if isinstance(self.score, Unset):
            score = UNSET
        else:
            score = self.score

        grade: None | str | Unset
        if isinstance(self.grade, Unset):
            grade = UNSET
        else:
            grade = self.grade

        scanned_at: None | str | Unset
        if isinstance(self.scanned_at, Unset):
            scanned_at = UNSET
        else:
            scanned_at = self.scanned_at

        total_findings: int | None | Unset
        if isinstance(self.total_findings, Unset):
            total_findings = UNSET
        else:
            total_findings = self.total_findings

        findings_by_severity: dict[str, Any] | None | Unset
        if isinstance(self.findings_by_severity, Unset):
            findings_by_severity = UNSET
        elif isinstance(self.findings_by_severity, ScoreResponseFindingsBySeverityType0):
            findings_by_severity = self.findings_by_severity.to_dict()
        else:
            findings_by_severity = self.findings_by_severity

        top_priorities: list[str] | None | Unset
        if isinstance(self.top_priorities, Unset):
            top_priorities = UNSET
        elif isinstance(self.top_priorities, list):
            top_priorities = self.top_priorities

        else:
            top_priorities = self.top_priorities

        message: None | str | Unset
        if isinstance(self.message, Unset):
            message = UNSET
        else:
            message = self.message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if scan_id is not UNSET:
            field_dict["scan_id"] = scan_id
        if score is not UNSET:
            field_dict["score"] = score
        if grade is not UNSET:
            field_dict["grade"] = grade
        if scanned_at is not UNSET:
            field_dict["scanned_at"] = scanned_at
        if total_findings is not UNSET:
            field_dict["total_findings"] = total_findings
        if findings_by_severity is not UNSET:
            field_dict["findings_by_severity"] = findings_by_severity
        if top_priorities is not UNSET:
            field_dict["top_priorities"] = top_priorities
        if message is not UNSET:
            field_dict["message"] = message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.score_response_findings_by_severity_type_0 import ScoreResponseFindingsBySeverityType0

        d = dict(src_dict)

        def _parse_scan_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scan_id = _parse_scan_id(d.pop("scan_id", UNSET))

        def _parse_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        score = _parse_score(d.pop("score", UNSET))

        def _parse_grade(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        grade = _parse_grade(d.pop("grade", UNSET))

        def _parse_scanned_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scanned_at = _parse_scanned_at(d.pop("scanned_at", UNSET))

        def _parse_total_findings(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        total_findings = _parse_total_findings(d.pop("total_findings", UNSET))

        def _parse_findings_by_severity(data: object) -> None | ScoreResponseFindingsBySeverityType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                findings_by_severity_type_0 = ScoreResponseFindingsBySeverityType0.from_dict(data)

                return findings_by_severity_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ScoreResponseFindingsBySeverityType0 | Unset, data)

        findings_by_severity = _parse_findings_by_severity(d.pop("findings_by_severity", UNSET))

        def _parse_top_priorities(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                top_priorities_type_0 = cast(list[str], data)

                return top_priorities_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        top_priorities = _parse_top_priorities(d.pop("top_priorities", UNSET))

        def _parse_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        message = _parse_message(d.pop("message", UNSET))

        score_response = cls(
            scan_id=scan_id,
            score=score,
            grade=grade,
            scanned_at=scanned_at,
            total_findings=total_findings,
            findings_by_severity=findings_by_severity,
            top_priorities=top_priorities,
            message=message,
        )

        score_response.additional_properties = d
        return score_response

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
