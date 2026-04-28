from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreatePlanRequest")


@_attrs_define
class CreatePlanRequest:
    """
    Attributes:
        name (str): Plan name
        incident_type (str): Type of incident
        priority (str): low/medium/high/critical
        org_id (str | Unset):  Default: 'default'.
        target_sources (list[str] | Unset): List of source IDs
        collection_steps (list[str] | Unset): Collection procedure steps
    """

    name: str
    incident_type: str
    priority: str
    org_id: str | Unset = "default"
    target_sources: list[str] | Unset = UNSET
    collection_steps: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        incident_type = self.incident_type

        priority = self.priority

        org_id = self.org_id

        target_sources: list[str] | Unset = UNSET
        if not isinstance(self.target_sources, Unset):
            target_sources = self.target_sources

        collection_steps: list[str] | Unset = UNSET
        if not isinstance(self.collection_steps, Unset):
            collection_steps = self.collection_steps

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "incident_type": incident_type,
                "priority": priority,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if target_sources is not UNSET:
            field_dict["target_sources"] = target_sources
        if collection_steps is not UNSET:
            field_dict["collection_steps"] = collection_steps

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        incident_type = d.pop("incident_type")

        priority = d.pop("priority")

        org_id = d.pop("org_id", UNSET)

        target_sources = cast(list[str], d.pop("target_sources", UNSET))

        collection_steps = cast(list[str], d.pop("collection_steps", UNSET))

        create_plan_request = cls(
            name=name,
            incident_type=incident_type,
            priority=priority,
            org_id=org_id,
            target_sources=target_sources,
            collection_steps=collection_steps,
        )

        create_plan_request.additional_properties = d
        return create_plan_request

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
