from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="QualityIssueResponse")


@_attrs_define
class QualityIssueResponse:
    """A single quality issue detected in TrustGraph.

    Attributes:
        issue_id (str):
        type_ (str):
        severity (str):
        description (str):
        entity_count (int):
        auto_fixable (bool):
        example_ids (list[str]):
        detected_at (str):
    """

    issue_id: str
    type_: str
    severity: str
    description: str
    entity_count: int
    auto_fixable: bool
    example_ids: list[str]
    detected_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        issue_id = self.issue_id

        type_ = self.type_

        severity = self.severity

        description = self.description

        entity_count = self.entity_count

        auto_fixable = self.auto_fixable

        example_ids = self.example_ids

        detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "issue_id": issue_id,
                "type": type_,
                "severity": severity,
                "description": description,
                "entity_count": entity_count,
                "auto_fixable": auto_fixable,
                "example_ids": example_ids,
                "detected_at": detected_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        issue_id = d.pop("issue_id")

        type_ = d.pop("type")

        severity = d.pop("severity")

        description = d.pop("description")

        entity_count = d.pop("entity_count")

        auto_fixable = d.pop("auto_fixable")

        example_ids = cast(list[str], d.pop("example_ids"))

        detected_at = d.pop("detected_at")

        quality_issue_response = cls(
            issue_id=issue_id,
            type_=type_,
            severity=severity,
            description=description,
            entity_count=entity_count,
            auto_fixable=auto_fixable,
            example_ids=example_ids,
            detected_at=detected_at,
        )

        quality_issue_response.additional_properties = d
        return quality_issue_response

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
