from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MapAttackPathRequest")


@_attrs_define
class MapAttackPathRequest:
    """
    Attributes:
        entry_asset_id (str): Internet-facing entry point asset ID
        target_asset_id (str): Internal target asset ID
        org_id (str | Unset): Organisation ID Default: 'default'.
        hops (list[str] | None | Unset): Intermediate hop asset IDs
        protocol (str | Unset): Network protocol Default: 'unknown'.
        techniques (list[str] | None | Unset): MITRE ATT&CK technique IDs
    """

    entry_asset_id: str
    target_asset_id: str
    org_id: str | Unset = "default"
    hops: list[str] | None | Unset = UNSET
    protocol: str | Unset = "unknown"
    techniques: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entry_asset_id = self.entry_asset_id

        target_asset_id = self.target_asset_id

        org_id = self.org_id

        hops: list[str] | None | Unset
        if isinstance(self.hops, Unset):
            hops = UNSET
        elif isinstance(self.hops, list):
            hops = self.hops

        else:
            hops = self.hops

        protocol = self.protocol

        techniques: list[str] | None | Unset
        if isinstance(self.techniques, Unset):
            techniques = UNSET
        elif isinstance(self.techniques, list):
            techniques = self.techniques

        else:
            techniques = self.techniques

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entry_asset_id": entry_asset_id,
                "target_asset_id": target_asset_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if hops is not UNSET:
            field_dict["hops"] = hops
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if techniques is not UNSET:
            field_dict["techniques"] = techniques

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        entry_asset_id = d.pop("entry_asset_id")

        target_asset_id = d.pop("target_asset_id")

        org_id = d.pop("org_id", UNSET)

        def _parse_hops(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                hops_type_0 = cast(list[str], data)

                return hops_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        hops = _parse_hops(d.pop("hops", UNSET))

        protocol = d.pop("protocol", UNSET)

        def _parse_techniques(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                techniques_type_0 = cast(list[str], data)

                return techniques_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        techniques = _parse_techniques(d.pop("techniques", UNSET))

        map_attack_path_request = cls(
            entry_asset_id=entry_asset_id,
            target_asset_id=target_asset_id,
            org_id=org_id,
            hops=hops,
            protocol=protocol,
            techniques=techniques,
        )

        map_attack_path_request.additional_properties = d
        return map_attack_path_request

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
