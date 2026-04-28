from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateHuntRequest")


@_attrs_define
class CreateHuntRequest:
    """
    Attributes:
        hunt_name (str): Name of the hunt
        org_id (str | Unset): Organisation ID Default: 'default'.
        hypothesis (str | Unset): Hunt hypothesis Default: ''.
        hunt_type (str | Unset): proactive/reactive/scheduled/automated Default: 'proactive'.
        technique_ids (list[str] | Unset): MITRE ATT&CK technique IDs
        hunter (str | Unset): Analyst running the hunt Default: ''.
    """

    hunt_name: str
    org_id: str | Unset = "default"
    hypothesis: str | Unset = ""
    hunt_type: str | Unset = "proactive"
    technique_ids: list[str] | Unset = UNSET
    hunter: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hunt_name = self.hunt_name

        org_id = self.org_id

        hypothesis = self.hypothesis

        hunt_type = self.hunt_type

        technique_ids: list[str] | Unset = UNSET
        if not isinstance(self.technique_ids, Unset):
            technique_ids = self.technique_ids

        hunter = self.hunter

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "hunt_name": hunt_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if hypothesis is not UNSET:
            field_dict["hypothesis"] = hypothesis
        if hunt_type is not UNSET:
            field_dict["hunt_type"] = hunt_type
        if technique_ids is not UNSET:
            field_dict["technique_ids"] = technique_ids
        if hunter is not UNSET:
            field_dict["hunter"] = hunter

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        hunt_name = d.pop("hunt_name")

        org_id = d.pop("org_id", UNSET)

        hypothesis = d.pop("hypothesis", UNSET)

        hunt_type = d.pop("hunt_type", UNSET)

        technique_ids = cast(list[str], d.pop("technique_ids", UNSET))

        hunter = d.pop("hunter", UNSET)

        create_hunt_request = cls(
            hunt_name=hunt_name,
            org_id=org_id,
            hypothesis=hypothesis,
            hunt_type=hunt_type,
            technique_ids=technique_ids,
            hunter=hunter,
        )

        create_hunt_request.additional_properties = d
        return create_hunt_request

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
