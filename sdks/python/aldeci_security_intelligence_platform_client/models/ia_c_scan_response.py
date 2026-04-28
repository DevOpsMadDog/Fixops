from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.ia_c_finding_response import IaCFindingResponse
    from ..models.ia_c_scan_response_metadata import IaCScanResponseMetadata


T = TypeVar("T", bound="IaCScanResponse")


@_attrs_define
class IaCScanResponse:
    """Response model for IaC scan.

    Attributes:
        scan_id (str):
        status (str):
        scanner (str):
        provider (str):
        target_path (str):
        findings_count (int):
        findings (list[IaCFindingResponse]):
        started_at (None | str):
        completed_at (None | str):
        duration_seconds (float | None):
        error_message (None | str):
        metadata (IaCScanResponseMetadata):
    """

    scan_id: str
    status: str
    scanner: str
    provider: str
    target_path: str
    findings_count: int
    findings: list[IaCFindingResponse]
    started_at: None | str
    completed_at: None | str
    duration_seconds: float | None
    error_message: None | str
    metadata: IaCScanResponseMetadata
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scan_id = self.scan_id

        status = self.status

        scanner = self.scanner

        provider = self.provider

        target_path = self.target_path

        findings_count = self.findings_count

        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        started_at: None | str
        started_at = self.started_at

        completed_at: None | str
        completed_at = self.completed_at

        duration_seconds: float | None
        duration_seconds = self.duration_seconds

        error_message: None | str
        error_message = self.error_message

        metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scan_id": scan_id,
                "status": status,
                "scanner": scanner,
                "provider": provider,
                "target_path": target_path,
                "findings_count": findings_count,
                "findings": findings,
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": duration_seconds,
                "error_message": error_message,
                "metadata": metadata,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ia_c_finding_response import IaCFindingResponse
        from ..models.ia_c_scan_response_metadata import IaCScanResponseMetadata

        d = dict(src_dict)
        scan_id = d.pop("scan_id")

        status = d.pop("status")

        scanner = d.pop("scanner")

        provider = d.pop("provider")

        target_path = d.pop("target_path")

        findings_count = d.pop("findings_count")

        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = IaCFindingResponse.from_dict(findings_item_data)

            findings.append(findings_item)

        def _parse_started_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        started_at = _parse_started_at(d.pop("started_at"))

        def _parse_completed_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        completed_at = _parse_completed_at(d.pop("completed_at"))

        def _parse_duration_seconds(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        duration_seconds = _parse_duration_seconds(d.pop("duration_seconds"))

        def _parse_error_message(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        error_message = _parse_error_message(d.pop("error_message"))

        metadata = IaCScanResponseMetadata.from_dict(d.pop("metadata"))

        ia_c_scan_response = cls(
            scan_id=scan_id,
            status=status,
            scanner=scanner,
            provider=provider,
            target_path=target_path,
            findings_count=findings_count,
            findings=findings,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
            error_message=error_message,
            metadata=metadata,
        )

        ia_c_scan_response.additional_properties = d
        return ia_c_scan_response

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
