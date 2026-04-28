from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.ia_c_finding_response_metadata import IaCFindingResponseMetadata


T = TypeVar("T", bound="IaCFindingResponse")


@_attrs_define
class IaCFindingResponse:
    """Response model for IaC finding.

    Attributes:
        id (str):
        provider (str):
        status (str):
        severity (str):
        title (str):
        description (str):
        file_path (str):
        line_number (int):
        resource_type (str):
        resource_name (str):
        rule_id (str):
        remediation (None | str):
        metadata (IaCFindingResponseMetadata):
        detected_at (str):
        resolved_at (None | str):
    """

    id: str
    provider: str
    status: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    resource_type: str
    resource_name: str
    rule_id: str
    remediation: None | str
    metadata: IaCFindingResponseMetadata
    detected_at: str
    resolved_at: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        provider = self.provider

        status = self.status

        severity = self.severity

        title = self.title

        description = self.description

        file_path = self.file_path

        line_number = self.line_number

        resource_type = self.resource_type

        resource_name = self.resource_name

        rule_id = self.rule_id

        remediation: None | str
        remediation = self.remediation

        metadata = self.metadata.to_dict()

        detected_at = self.detected_at

        resolved_at: None | str
        resolved_at = self.resolved_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "provider": provider,
                "status": status,
                "severity": severity,
                "title": title,
                "description": description,
                "file_path": file_path,
                "line_number": line_number,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "rule_id": rule_id,
                "remediation": remediation,
                "metadata": metadata,
                "detected_at": detected_at,
                "resolved_at": resolved_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ia_c_finding_response_metadata import IaCFindingResponseMetadata

        d = dict(src_dict)
        id = d.pop("id")

        provider = d.pop("provider")

        status = d.pop("status")

        severity = d.pop("severity")

        title = d.pop("title")

        description = d.pop("description")

        file_path = d.pop("file_path")

        line_number = d.pop("line_number")

        resource_type = d.pop("resource_type")

        resource_name = d.pop("resource_name")

        rule_id = d.pop("rule_id")

        def _parse_remediation(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        remediation = _parse_remediation(d.pop("remediation"))

        metadata = IaCFindingResponseMetadata.from_dict(d.pop("metadata"))

        detected_at = d.pop("detected_at")

        def _parse_resolved_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        resolved_at = _parse_resolved_at(d.pop("resolved_at"))

        ia_c_finding_response = cls(
            id=id,
            provider=provider,
            status=status,
            severity=severity,
            title=title,
            description=description,
            file_path=file_path,
            line_number=line_number,
            resource_type=resource_type,
            resource_name=resource_name,
            rule_id=rule_id,
            remediation=remediation,
            metadata=metadata,
            detected_at=detected_at,
            resolved_at=resolved_at,
        )

        ia_c_finding_response.additional_properties = d
        return ia_c_finding_response

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
