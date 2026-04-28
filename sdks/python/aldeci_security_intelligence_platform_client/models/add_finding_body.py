from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddFindingBody")


@_attrs_define
class AddFindingBody:
    """
    Attributes:
        component (str): Component with the finding
        finding_type (str): design-flaw | missing-control | weak-implementation | configuration | dependency-risk |
            data-exposure
        title (str): Short finding title
        description (str | Unset): Detailed description Default: ''.
        severity (str | Unset): critical | high | medium | low | info Default: 'medium'.
        recommendation (str | Unset): Remediation recommendation Default: ''.
    """

    component: str
    finding_type: str
    title: str
    description: str | Unset = ""
    severity: str | Unset = "medium"
    recommendation: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        component = self.component

        finding_type = self.finding_type

        title = self.title

        description = self.description

        severity = self.severity

        recommendation = self.recommendation

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "component": component,
                "finding_type": finding_type,
                "title": title,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if severity is not UNSET:
            field_dict["severity"] = severity
        if recommendation is not UNSET:
            field_dict["recommendation"] = recommendation

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        component = d.pop("component")

        finding_type = d.pop("finding_type")

        title = d.pop("title")

        description = d.pop("description", UNSET)

        severity = d.pop("severity", UNSET)

        recommendation = d.pop("recommendation", UNSET)

        add_finding_body = cls(
            component=component,
            finding_type=finding_type,
            title=title,
            description=description,
            severity=severity,
            recommendation=recommendation,
        )

        add_finding_body.additional_properties = d
        return add_finding_body

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
