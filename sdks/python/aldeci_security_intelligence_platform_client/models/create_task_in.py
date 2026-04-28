from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateTaskIn")


@_attrs_define
class CreateTaskIn:
    """
    Attributes:
        title (str): Short description of the remediation task
        cve_id (str | Unset): CVE identifier e.g. CVE-2024-1234 Default: ''.
        severity (str | Unset): critical|high|medium|low|info Default: 'medium'.
        asset_id (str | Unset): Asset identifier Default: ''.
        asset_name (str | Unset): Human-readable asset name Default: ''.
        assigned_to (str | Unset): Assignee username or team Default: ''.
        due_date (str | Unset): Due date ISO 8601 e.g. 2025-06-01 Default: ''.
        remediation_type (str | Unset): patch|config|workaround|accept Default: 'patch'.
    """

    title: str
    cve_id: str | Unset = ""
    severity: str | Unset = "medium"
    asset_id: str | Unset = ""
    asset_name: str | Unset = ""
    assigned_to: str | Unset = ""
    due_date: str | Unset = ""
    remediation_type: str | Unset = "patch"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        cve_id = self.cve_id

        severity = self.severity

        asset_id = self.asset_id

        asset_name = self.asset_name

        assigned_to = self.assigned_to

        due_date = self.due_date

        remediation_type = self.remediation_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if severity is not UNSET:
            field_dict["severity"] = severity
        if asset_id is not UNSET:
            field_dict["asset_id"] = asset_id
        if asset_name is not UNSET:
            field_dict["asset_name"] = asset_name
        if assigned_to is not UNSET:
            field_dict["assigned_to"] = assigned_to
        if due_date is not UNSET:
            field_dict["due_date"] = due_date
        if remediation_type is not UNSET:
            field_dict["remediation_type"] = remediation_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        cve_id = d.pop("cve_id", UNSET)

        severity = d.pop("severity", UNSET)

        asset_id = d.pop("asset_id", UNSET)

        asset_name = d.pop("asset_name", UNSET)

        assigned_to = d.pop("assigned_to", UNSET)

        due_date = d.pop("due_date", UNSET)

        remediation_type = d.pop("remediation_type", UNSET)

        create_task_in = cls(
            title=title,
            cve_id=cve_id,
            severity=severity,
            asset_id=asset_id,
            asset_name=asset_name,
            assigned_to=assigned_to,
            due_date=due_date,
            remediation_type=remediation_type,
        )

        create_task_in.additional_properties = d
        return create_task_in

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
