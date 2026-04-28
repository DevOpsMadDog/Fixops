from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatModelRequest")


@_attrs_define
class ThreatModelRequest:
    """Request model for threat model definition.

    Attributes:
        name (str): Name of the threat model
        description (str | Unset): Description Default: ''.
        categories (list[str] | Unset): Threat categories
        attack_vectors (list[str] | Unset): Attack vectors
        compliance_frameworks (list[str] | Unset): Compliance frameworks
        priority (int | Unset): Priority (1-10) Default: 5.
    """

    name: str
    description: str | Unset = ""
    categories: list[str] | Unset = UNSET
    attack_vectors: list[str] | Unset = UNSET
    compliance_frameworks: list[str] | Unset = UNSET
    priority: int | Unset = 5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        categories: list[str] | Unset = UNSET
        if not isinstance(self.categories, Unset):
            categories = self.categories

        attack_vectors: list[str] | Unset = UNSET
        if not isinstance(self.attack_vectors, Unset):
            attack_vectors = self.attack_vectors

        compliance_frameworks: list[str] | Unset = UNSET
        if not isinstance(self.compliance_frameworks, Unset):
            compliance_frameworks = self.compliance_frameworks

        priority = self.priority

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if categories is not UNSET:
            field_dict["categories"] = categories
        if attack_vectors is not UNSET:
            field_dict["attack_vectors"] = attack_vectors
        if compliance_frameworks is not UNSET:
            field_dict["compliance_frameworks"] = compliance_frameworks
        if priority is not UNSET:
            field_dict["priority"] = priority

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description", UNSET)

        categories = cast(list[str], d.pop("categories", UNSET))

        attack_vectors = cast(list[str], d.pop("attack_vectors", UNSET))

        compliance_frameworks = cast(list[str], d.pop("compliance_frameworks", UNSET))

        priority = d.pop("priority", UNSET)

        threat_model_request = cls(
            name=name,
            description=description,
            categories=categories,
            attack_vectors=attack_vectors,
            compliance_frameworks=compliance_frameworks,
            priority=priority,
        )

        threat_model_request.additional_properties = d
        return threat_model_request

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
