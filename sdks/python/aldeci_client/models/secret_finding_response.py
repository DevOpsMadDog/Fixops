from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.secret_finding_response_metadata import SecretFindingResponseMetadata


T = TypeVar("T", bound="SecretFindingResponse")


@_attrs_define
class SecretFindingResponse:
    """Response model for secret finding.

    Attributes:
        id (str):
        secret_type (str):
        status (str):
        file_path (str):
        line_number (int):
        repository (str):
        branch (str):
        commit_hash (None | str):
        matched_pattern (None | str):
        entropy_score (float | None):
        metadata (SecretFindingResponseMetadata):
        detected_at (str):
        resolved_at (None | str):
    """

    id: str
    secret_type: str
    status: str
    file_path: str
    line_number: int
    repository: str
    branch: str
    commit_hash: None | str
    matched_pattern: None | str
    entropy_score: float | None
    metadata: SecretFindingResponseMetadata
    detected_at: str
    resolved_at: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        secret_type = self.secret_type

        status = self.status

        file_path = self.file_path

        line_number = self.line_number

        repository = self.repository

        branch = self.branch

        commit_hash: None | str
        commit_hash = self.commit_hash

        matched_pattern: None | str
        matched_pattern = self.matched_pattern

        entropy_score: float | None
        entropy_score = self.entropy_score

        metadata = self.metadata.to_dict()

        detected_at = self.detected_at

        resolved_at: None | str
        resolved_at = self.resolved_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "secret_type": secret_type,
                "status": status,
                "file_path": file_path,
                "line_number": line_number,
                "repository": repository,
                "branch": branch,
                "commit_hash": commit_hash,
                "matched_pattern": matched_pattern,
                "entropy_score": entropy_score,
                "metadata": metadata,
                "detected_at": detected_at,
                "resolved_at": resolved_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.secret_finding_response_metadata import SecretFindingResponseMetadata

        d = dict(src_dict)
        id = d.pop("id")

        secret_type = d.pop("secret_type")

        status = d.pop("status")

        file_path = d.pop("file_path")

        line_number = d.pop("line_number")

        repository = d.pop("repository")

        branch = d.pop("branch")

        def _parse_commit_hash(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        commit_hash = _parse_commit_hash(d.pop("commit_hash"))

        def _parse_matched_pattern(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        matched_pattern = _parse_matched_pattern(d.pop("matched_pattern"))

        def _parse_entropy_score(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        entropy_score = _parse_entropy_score(d.pop("entropy_score"))

        metadata = SecretFindingResponseMetadata.from_dict(d.pop("metadata"))

        detected_at = d.pop("detected_at")

        def _parse_resolved_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        resolved_at = _parse_resolved_at(d.pop("resolved_at"))

        secret_finding_response = cls(
            id=id,
            secret_type=secret_type,
            status=status,
            file_path=file_path,
            line_number=line_number,
            repository=repository,
            branch=branch,
            commit_hash=commit_hash,
            matched_pattern=matched_pattern,
            entropy_score=entropy_score,
            metadata=metadata,
            detected_at=detected_at,
            resolved_at=resolved_at,
        )

        secret_finding_response.additional_properties = d
        return secret_finding_response

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
