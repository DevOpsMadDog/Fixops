from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateRoadmapItemRequest")


@_attrs_define
class CreateRoadmapItemRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        domain (str): Security domain
        capability (str): Capability to improve
        current_level (int): Current maturity level
        target_level (int): Target maturity level
        priority (str | Unset): critical/high/medium/low Default: 'medium'.
        effort (str | Unset): low/medium/high/very-high Default: 'medium'.
        timeline (str | Unset): Planned timeline (e.g. Q3 2026) Default: ''.
        owner (str | Unset): Responsible owner Default: ''.
    """

    org_id: str
    domain: str
    capability: str
    current_level: int
    target_level: int
    priority: str | Unset = "medium"
    effort: str | Unset = "medium"
    timeline: str | Unset = ""
    owner: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        domain = self.domain

        capability = self.capability

        current_level = self.current_level

        target_level = self.target_level

        priority = self.priority

        effort = self.effort

        timeline = self.timeline

        owner = self.owner

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "domain": domain,
                "capability": capability,
                "current_level": current_level,
                "target_level": target_level,
            }
        )
        if priority is not UNSET:
            field_dict["priority"] = priority
        if effort is not UNSET:
            field_dict["effort"] = effort
        if timeline is not UNSET:
            field_dict["timeline"] = timeline
        if owner is not UNSET:
            field_dict["owner"] = owner

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        domain = d.pop("domain")

        capability = d.pop("capability")

        current_level = d.pop("current_level")

        target_level = d.pop("target_level")

        priority = d.pop("priority", UNSET)

        effort = d.pop("effort", UNSET)

        timeline = d.pop("timeline", UNSET)

        owner = d.pop("owner", UNSET)

        create_roadmap_item_request = cls(
            org_id=org_id,
            domain=domain,
            capability=capability,
            current_level=current_level,
            target_level=target_level,
            priority=priority,
            effort=effort,
            timeline=timeline,
            owner=owner,
        )

        create_roadmap_item_request.additional_properties = d
        return create_roadmap_item_request

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
