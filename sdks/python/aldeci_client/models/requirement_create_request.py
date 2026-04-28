from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RequirementCreateRequest")


@_attrs_define
class RequirementCreateRequest:
    """
    Attributes:
        framework (str):
        control_id (str):
        control_name (str):
        evidence_types (list[str]):
    """

    framework: str
    control_id: str
    control_name: str
    evidence_types: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        control_id = self.control_id

        control_name = self.control_name

        evidence_types = self.evidence_types

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
                "control_id": control_id,
                "control_name": control_name,
                "evidence_types": evidence_types,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        framework = d.pop("framework")

        control_id = d.pop("control_id")

        control_name = d.pop("control_name")

        evidence_types = cast(list[str], d.pop("evidence_types"))

        requirement_create_request = cls(
            framework=framework,
            control_id=control_id,
            control_name=control_name,
            evidence_types=evidence_types,
        )

        requirement_create_request.additional_properties = d
        return requirement_create_request

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
