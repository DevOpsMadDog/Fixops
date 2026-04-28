from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateWorkflowRequest")


@_attrs_define
class CreateWorkflowRequest:
    """
    Attributes:
        title (str): Short descriptive title for the workflow
        cve_id (None | str | Unset): CVE identifier (e.g. CVE-2024-1234)
        asset_id (None | str | Unset): Affected asset identifier
        workflow_type (str | Unset): patch | config_change | compensating_control | accept_risk | false_positive
            Default: 'patch'.
        priority (str | Unset): critical | high | medium | low Default: 'medium'.
        sla_tier (str | Unset): p1 (1d) | p2 (7d) | p3 (30d) | p4 (90d) Default: 'p3'.
        assigned_to (None | str | Unset): Assignee username or team
        notes (None | str | Unset): Initial notes
    """

    title: str
    cve_id: None | str | Unset = UNSET
    asset_id: None | str | Unset = UNSET
    workflow_type: str | Unset = "patch"
    priority: str | Unset = "medium"
    sla_tier: str | Unset = "p3"
    assigned_to: None | str | Unset = UNSET
    notes: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        asset_id: None | str | Unset
        if isinstance(self.asset_id, Unset):
            asset_id = UNSET
        else:
            asset_id = self.asset_id

        workflow_type = self.workflow_type

        priority = self.priority

        sla_tier = self.sla_tier

        assigned_to: None | str | Unset
        if isinstance(self.assigned_to, Unset):
            assigned_to = UNSET
        else:
            assigned_to = self.assigned_to

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if asset_id is not UNSET:
            field_dict["asset_id"] = asset_id
        if workflow_type is not UNSET:
            field_dict["workflow_type"] = workflow_type
        if priority is not UNSET:
            field_dict["priority"] = priority
        if sla_tier is not UNSET:
            field_dict["sla_tier"] = sla_tier
        if assigned_to is not UNSET:
            field_dict["assigned_to"] = assigned_to
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        def _parse_asset_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_id = _parse_asset_id(d.pop("asset_id", UNSET))

        workflow_type = d.pop("workflow_type", UNSET)

        priority = d.pop("priority", UNSET)

        sla_tier = d.pop("sla_tier", UNSET)

        def _parse_assigned_to(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assigned_to = _parse_assigned_to(d.pop("assigned_to", UNSET))

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        create_workflow_request = cls(
            title=title,
            cve_id=cve_id,
            asset_id=asset_id,
            workflow_type=workflow_type,
            priority=priority,
            sla_tier=sla_tier,
            assigned_to=assigned_to,
            notes=notes,
        )

        create_workflow_request.additional_properties = d
        return create_workflow_request

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
