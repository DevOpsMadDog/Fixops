from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VirtualPatchRequest")


@_attrs_define
class VirtualPatchRequest:
    """
    Attributes:
        cve_id (str):
        endpoint (str):
        attack_vector (str):
        description (str | Unset):  Default: ''.
    """

    cve_id: str
    endpoint: str
    attack_vector: str
    description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        endpoint = self.endpoint

        attack_vector = self.attack_vector

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "endpoint": endpoint,
                "attack_vector": attack_vector,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        endpoint = d.pop("endpoint")

        attack_vector = d.pop("attack_vector")

        description = d.pop("description", UNSET)

        virtual_patch_request = cls(
            cve_id=cve_id,
            endpoint=endpoint,
            attack_vector=attack_vector,
            description=description,
        )

        virtual_patch_request.additional_properties = d
        return virtual_patch_request

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
