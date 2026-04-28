from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ContainIncidentRequest")


@_attrs_define
class ContainIncidentRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        blast_radius (str | Unset): Blast radius description Default: 'unknown'.
    """

    org_id: str
    blast_radius: str | Unset = "unknown"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        blast_radius = self.blast_radius

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if blast_radius is not UNSET:
            field_dict["blast_radius"] = blast_radius

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        blast_radius = d.pop("blast_radius", UNSET)

        contain_incident_request = cls(
            org_id=org_id,
            blast_radius=blast_radius,
        )

        contain_incident_request.additional_properties = d
        return contain_incident_request

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
