from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.maintenance_issue_response_extra import MaintenanceIssueResponseExtra


T = TypeVar("T", bound="MaintenanceIssueResponse")


@_attrs_define
class MaintenanceIssueResponse:
    """A single detected integrity issue.

    Attributes:
        issue_id (str):
        severity (str):
        issue_type (str):
        entity_id (str):
        description (str):
        suggested_fix (str):
        core_id (int):
        extra (MaintenanceIssueResponseExtra):
        detected_at (str):
    """

    issue_id: str
    severity: str
    issue_type: str
    entity_id: str
    description: str
    suggested_fix: str
    core_id: int
    extra: MaintenanceIssueResponseExtra
    detected_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        issue_id = self.issue_id

        severity = self.severity

        issue_type = self.issue_type

        entity_id = self.entity_id

        description = self.description

        suggested_fix = self.suggested_fix

        core_id = self.core_id

        extra = self.extra.to_dict()

        detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "issue_id": issue_id,
                "severity": severity,
                "issue_type": issue_type,
                "entity_id": entity_id,
                "description": description,
                "suggested_fix": suggested_fix,
                "core_id": core_id,
                "extra": extra,
                "detected_at": detected_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.maintenance_issue_response_extra import MaintenanceIssueResponseExtra

        d = dict(src_dict)
        issue_id = d.pop("issue_id")

        severity = d.pop("severity")

        issue_type = d.pop("issue_type")

        entity_id = d.pop("entity_id")

        description = d.pop("description")

        suggested_fix = d.pop("suggested_fix")

        core_id = d.pop("core_id")

        extra = MaintenanceIssueResponseExtra.from_dict(d.pop("extra"))

        detected_at = d.pop("detected_at")

        maintenance_issue_response = cls(
            issue_id=issue_id,
            severity=severity,
            issue_type=issue_type,
            entity_id=entity_id,
            description=description,
            suggested_fix=suggested_fix,
            core_id=core_id,
            extra=extra,
            detected_at=detected_at,
        )

        maintenance_issue_response.additional_properties = d
        return maintenance_issue_response

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
