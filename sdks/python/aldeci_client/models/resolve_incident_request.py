from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ResolveIncidentRequest")


@_attrs_define
class ResolveIncidentRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        root_cause (str | Unset): Root cause analysis Default: ''.
    """

    org_id: str
    root_cause: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        root_cause = self.root_cause

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if root_cause is not UNSET:
            field_dict["root_cause"] = root_cause

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        root_cause = d.pop("root_cause", UNSET)

        resolve_incident_request = cls(
            org_id=org_id,
            root_cause=root_cause,
        )

        resolve_incident_request.additional_properties = d
        return resolve_incident_request

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
