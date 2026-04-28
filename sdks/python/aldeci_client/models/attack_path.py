from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AttackPath")


@_attrs_define
class AttackPath:
    """Modelled attack path from internet into internal zone.

    Attributes:
        entry_asset_id (str):
        target_asset_id (str):
        id (str | Unset):
        org_id (str | Unset):  Default: 'default'.
        name (str | Unset):  Default: ''.
        hops (list[str] | Unset):
        protocol (str | Unset):  Default: 'unknown'.
        path_risk_score (float | Unset):  Default: 0.0.
        blast_radius (int | Unset):  Default: 0.
        is_choke_point (bool | Unset):  Default: False.
        techniques (list[str] | Unset):
        description (str | Unset):  Default: ''.
        created_at (str | Unset):
    """

    entry_asset_id: str
    target_asset_id: str
    id: str | Unset = UNSET
    org_id: str | Unset = "default"
    name: str | Unset = ""
    hops: list[str] | Unset = UNSET
    protocol: str | Unset = "unknown"
    path_risk_score: float | Unset = 0.0
    blast_radius: int | Unset = 0
    is_choke_point: bool | Unset = False
    techniques: list[str] | Unset = UNSET
    description: str | Unset = ""
    created_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entry_asset_id = self.entry_asset_id

        target_asset_id = self.target_asset_id

        id = self.id

        org_id = self.org_id

        name = self.name

        hops: list[str] | Unset = UNSET
        if not isinstance(self.hops, Unset):
            hops = self.hops

        protocol = self.protocol

        path_risk_score = self.path_risk_score

        blast_radius = self.blast_radius

        is_choke_point = self.is_choke_point

        techniques: list[str] | Unset = UNSET
        if not isinstance(self.techniques, Unset):
            techniques = self.techniques

        description = self.description

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entry_asset_id": entry_asset_id,
                "target_asset_id": target_asset_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if name is not UNSET:
            field_dict["name"] = name
        if hops is not UNSET:
            field_dict["hops"] = hops
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if path_risk_score is not UNSET:
            field_dict["path_risk_score"] = path_risk_score
        if blast_radius is not UNSET:
            field_dict["blast_radius"] = blast_radius
        if is_choke_point is not UNSET:
            field_dict["is_choke_point"] = is_choke_point
        if techniques is not UNSET:
            field_dict["techniques"] = techniques
        if description is not UNSET:
            field_dict["description"] = description
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        entry_asset_id = d.pop("entry_asset_id")

        target_asset_id = d.pop("target_asset_id")

        id = d.pop("id", UNSET)

        org_id = d.pop("org_id", UNSET)

        name = d.pop("name", UNSET)

        hops = cast(list[str], d.pop("hops", UNSET))

        protocol = d.pop("protocol", UNSET)

        path_risk_score = d.pop("path_risk_score", UNSET)

        blast_radius = d.pop("blast_radius", UNSET)

        is_choke_point = d.pop("is_choke_point", UNSET)

        techniques = cast(list[str], d.pop("techniques", UNSET))

        description = d.pop("description", UNSET)

        created_at = d.pop("created_at", UNSET)

        attack_path = cls(
            entry_asset_id=entry_asset_id,
            target_asset_id=target_asset_id,
            id=id,
            org_id=org_id,
            name=name,
            hops=hops,
            protocol=protocol,
            path_risk_score=path_risk_score,
            blast_radius=blast_radius,
            is_choke_point=is_choke_point,
            techniques=techniques,
            description=description,
            created_at=created_at,
        )

        attack_path.additional_properties = d
        return attack_path

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
