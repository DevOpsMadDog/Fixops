from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DemandCreate")


@_attrs_define
class DemandCreate:
    """
    Attributes:
        demand_name (str):
        domain (str | Unset):  Default: 'detection'.
        priority (str | Unset):  Default: 'medium'.
        required_fte (float | Unset):  Default: 1.0.
        required_skills (list[str] | Unset):
        timeline (str | Unset):  Default: 'q1'.
    """

    demand_name: str
    domain: str | Unset = "detection"
    priority: str | Unset = "medium"
    required_fte: float | Unset = 1.0
    required_skills: list[str] | Unset = UNSET
    timeline: str | Unset = "q1"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        demand_name = self.demand_name

        domain = self.domain

        priority = self.priority

        required_fte = self.required_fte

        required_skills: list[str] | Unset = UNSET
        if not isinstance(self.required_skills, Unset):
            required_skills = self.required_skills

        timeline = self.timeline

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "demand_name": demand_name,
            }
        )
        if domain is not UNSET:
            field_dict["domain"] = domain
        if priority is not UNSET:
            field_dict["priority"] = priority
        if required_fte is not UNSET:
            field_dict["required_fte"] = required_fte
        if required_skills is not UNSET:
            field_dict["required_skills"] = required_skills
        if timeline is not UNSET:
            field_dict["timeline"] = timeline

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        demand_name = d.pop("demand_name")

        domain = d.pop("domain", UNSET)

        priority = d.pop("priority", UNSET)

        required_fte = d.pop("required_fte", UNSET)

        required_skills = cast(list[str], d.pop("required_skills", UNSET))

        timeline = d.pop("timeline", UNSET)

        demand_create = cls(
            demand_name=demand_name,
            domain=domain,
            priority=priority,
            required_fte=required_fte,
            required_skills=required_skills,
            timeline=timeline,
        )

        demand_create.additional_properties = d
        return demand_create

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
