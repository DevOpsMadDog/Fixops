from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.import_summary_response_severity_breakdown import ImportSummaryResponseSeverityBreakdown


T = TypeVar("T", bound="ImportSummaryResponse")


@_attrs_define
class ImportSummaryResponse:
    """Import history entry (findings omitted for brevity).

    Attributes:
        import_id (str):
        org_id (str):
        started_at (str):
        completed_at (str):
        status (str):
        is_mock (bool):
        findings_count (int):
        severity_breakdown (ImportSummaryResponseSeverityBreakdown):
        error (None | str | Unset):
    """

    import_id: str
    org_id: str
    started_at: str
    completed_at: str
    status: str
    is_mock: bool
    findings_count: int
    severity_breakdown: ImportSummaryResponseSeverityBreakdown
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        import_id = self.import_id

        org_id = self.org_id

        started_at = self.started_at

        completed_at = self.completed_at

        status = self.status

        is_mock = self.is_mock

        findings_count = self.findings_count

        severity_breakdown = self.severity_breakdown.to_dict()

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "import_id": import_id,
                "org_id": org_id,
                "started_at": started_at,
                "completed_at": completed_at,
                "status": status,
                "is_mock": is_mock,
                "findings_count": findings_count,
                "severity_breakdown": severity_breakdown,
            }
        )
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.import_summary_response_severity_breakdown import ImportSummaryResponseSeverityBreakdown

        d = dict(src_dict)
        import_id = d.pop("import_id")

        org_id = d.pop("org_id")

        started_at = d.pop("started_at")

        completed_at = d.pop("completed_at")

        status = d.pop("status")

        is_mock = d.pop("is_mock")

        findings_count = d.pop("findings_count")

        severity_breakdown = ImportSummaryResponseSeverityBreakdown.from_dict(d.pop("severity_breakdown"))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        import_summary_response = cls(
            import_id=import_id,
            org_id=org_id,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            is_mock=is_mock,
            findings_count=findings_count,
            severity_breakdown=severity_breakdown,
            error=error,
        )

        import_summary_response.additional_properties = d
        return import_summary_response

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
