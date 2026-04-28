from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatModelCreate")


@_attrs_define
class ThreatModelCreate:
    """
    Attributes:
        name (str):
        description (str | Unset):  Default: ''.
        system_type (str | Unset):  Default: 'web_app'.
        methodology (str | Unset):  Default: 'STRIDE'.
        status (str | Unset):  Default: 'draft'.
        data_classification (str | Unset):  Default: 'internal'.
        trust_boundaries (list[str] | Unset):
        components (list[str] | Unset):
    """

    name: str
    description: str | Unset = ""
    system_type: str | Unset = "web_app"
    methodology: str | Unset = "STRIDE"
    status: str | Unset = "draft"
    data_classification: str | Unset = "internal"
    trust_boundaries: list[str] | Unset = UNSET
    components: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        system_type = self.system_type

        methodology = self.methodology

        status = self.status

        data_classification = self.data_classification

        trust_boundaries: list[str] | Unset = UNSET
        if not isinstance(self.trust_boundaries, Unset):
            trust_boundaries = self.trust_boundaries

        components: list[str] | Unset = UNSET
        if not isinstance(self.components, Unset):
            components = self.components

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if system_type is not UNSET:
            field_dict["system_type"] = system_type
        if methodology is not UNSET:
            field_dict["methodology"] = methodology
        if status is not UNSET:
            field_dict["status"] = status
        if data_classification is not UNSET:
            field_dict["data_classification"] = data_classification
        if trust_boundaries is not UNSET:
            field_dict["trust_boundaries"] = trust_boundaries
        if components is not UNSET:
            field_dict["components"] = components

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description", UNSET)

        system_type = d.pop("system_type", UNSET)

        methodology = d.pop("methodology", UNSET)

        status = d.pop("status", UNSET)

        data_classification = d.pop("data_classification", UNSET)

        trust_boundaries = cast(list[str], d.pop("trust_boundaries", UNSET))

        components = cast(list[str], d.pop("components", UNSET))

        threat_model_create = cls(
            name=name,
            description=description,
            system_type=system_type,
            methodology=methodology,
            status=status,
            data_classification=data_classification,
            trust_boundaries=trust_boundaries,
            components=components,
        )

        threat_model_create.additional_properties = d
        return threat_model_create

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
