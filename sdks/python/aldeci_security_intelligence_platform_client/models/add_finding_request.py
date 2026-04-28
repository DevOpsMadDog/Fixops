from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddFindingRequest")


@_attrs_define
class AddFindingRequest:
    """
    Attributes:
        category (str | Unset):  Default: 'misconfiguration'.
        severity (str | Unset):  Default: 'medium'.
        title (str | Unset):  Default: ''.
        description (str | Unset):  Default: ''.
        remediation (str | Unset):  Default: ''.
        cve_id (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'open'.
        detected_at (None | str | Unset):
    """

    category: str | Unset = "misconfiguration"
    severity: str | Unset = "medium"
    title: str | Unset = ""
    description: str | Unset = ""
    remediation: str | Unset = ""
    cve_id: str | Unset = ""
    status: str | Unset = "open"
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        category = self.category

        severity = self.severity

        title = self.title

        description = self.description

        remediation = self.remediation

        cve_id = self.cve_id

        status = self.status

        detected_at: None | str | Unset
        if isinstance(self.detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if category is not UNSET:
            field_dict["category"] = category
        if severity is not UNSET:
            field_dict["severity"] = severity
        if title is not UNSET:
            field_dict["title"] = title
        if description is not UNSET:
            field_dict["description"] = description
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if status is not UNSET:
            field_dict["status"] = status
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        category = d.pop("category", UNSET)

        severity = d.pop("severity", UNSET)

        title = d.pop("title", UNSET)

        description = d.pop("description", UNSET)

        remediation = d.pop("remediation", UNSET)

        cve_id = d.pop("cve_id", UNSET)

        status = d.pop("status", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        add_finding_request = cls(
            category=category,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            cve_id=cve_id,
            status=status,
            detected_at=detected_at,
        )

        add_finding_request.additional_properties = d
        return add_finding_request

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
