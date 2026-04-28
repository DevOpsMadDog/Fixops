from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.secret_finding_response import SecretFindingResponse
    from ..models.secrets_scan_response_metadata import SecretsScanResponseMetadata


T = TypeVar("T", bound="SecretsScanResponse")


@_attrs_define
class SecretsScanResponse:
    """Response model for secrets scan.

    Attributes:
        scan_id (str):
        status (str):
        scanner (str):
        target_path (str):
        repository (str):
        branch (str):
        findings_count (int):
        findings (list[SecretFindingResponse]):
        started_at (None | str):
        completed_at (None | str):
        duration_seconds (float | None):
        error_message (None | str):
        metadata (SecretsScanResponseMetadata):
    """

    scan_id: str
    status: str
    scanner: str
    target_path: str
    repository: str
    branch: str
    findings_count: int
    findings: list[SecretFindingResponse]
    started_at: None | str
    completed_at: None | str
    duration_seconds: float | None
    error_message: None | str
    metadata: SecretsScanResponseMetadata
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scan_id = self.scan_id

        status = self.status

        scanner = self.scanner

        target_path = self.target_path

        repository = self.repository

        branch = self.branch

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
                "target_path": target_path,
                "repository": repository,
                "branch": branch,
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
        from ..models.secret_finding_response import SecretFindingResponse
        from ..models.secrets_scan_response_metadata import SecretsScanResponseMetadata

        d = dict(src_dict)
        scan_id = d.pop("scan_id")

        status = d.pop("status")

        scanner = d.pop("scanner")

        target_path = d.pop("target_path")

        repository = d.pop("repository")

        branch = d.pop("branch")

        findings_count = d.pop("findings_count")

        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = SecretFindingResponse.from_dict(findings_item_data)

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

        metadata = SecretsScanResponseMetadata.from_dict(d.pop("metadata"))

        secrets_scan_response = cls(
            scan_id=scan_id,
            status=status,
            scanner=scanner,
            target_path=target_path,
            repository=repository,
            branch=branch,
            findings_count=findings_count,
            findings=findings,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
            error_message=error_message,
            metadata=metadata,
        )

        secrets_scan_response.additional_properties = d
        return secrets_scan_response

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
