from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.zone_type import ZoneType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.define_zone_request_metadata import DefineZoneRequestMetadata


T = TypeVar("T", bound="DefineZoneRequest")


@_attrs_define
class DefineZoneRequest:
    """
    Attributes:
        name (str): Zone name
        type_ (ZoneType):
        cidrs (list[str] | Unset): CIDR blocks
        assets (list[str] | Unset): Asset IDs
        trust_level (int | Unset): Trust level 0-100 Default: 50.
        metadata (DefineZoneRequestMetadata | Unset):
    """

    name: str
    type_: ZoneType
    cidrs: list[str] | Unset = UNSET
    assets: list[str] | Unset = UNSET
    trust_level: int | Unset = 50
    metadata: DefineZoneRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        type_ = self.type_.value

        cidrs: list[str] | Unset = UNSET
        if not isinstance(self.cidrs, Unset):
            cidrs = self.cidrs

        assets: list[str] | Unset = UNSET
        if not isinstance(self.assets, Unset):
            assets = self.assets

        trust_level = self.trust_level

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "type": type_,
            }
        )
        if cidrs is not UNSET:
            field_dict["cidrs"] = cidrs
        if assets is not UNSET:
            field_dict["assets"] = assets
        if trust_level is not UNSET:
            field_dict["trust_level"] = trust_level
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.define_zone_request_metadata import DefineZoneRequestMetadata

        d = dict(src_dict)
        name = d.pop("name")

        type_ = ZoneType(d.pop("type"))

        cidrs = cast(list[str], d.pop("cidrs", UNSET))

        assets = cast(list[str], d.pop("assets", UNSET))

        trust_level = d.pop("trust_level", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: DefineZoneRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = DefineZoneRequestMetadata.from_dict(_metadata)

        define_zone_request = cls(
            name=name,
            type_=type_,
            cidrs=cidrs,
            assets=assets,
            trust_level=trust_level,
            metadata=metadata,
        )

        define_zone_request.additional_properties = d
        return define_zone_request

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
