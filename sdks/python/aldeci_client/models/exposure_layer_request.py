from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExposureLayerRequest")


@_attrs_define
class ExposureLayerRequest:
    """
    Attributes:
        asset_ref (str): Opaque reference to the asset
        exposure_layer (str): Network-zone tag: external-internet / dmz / internal / restricted / isolated
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    asset_ref: str
    exposure_layer: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_ref = self.asset_ref

        exposure_layer = self.exposure_layer

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_ref": asset_ref,
                "exposure_layer": exposure_layer,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_ref = d.pop("asset_ref")

        exposure_layer = d.pop("exposure_layer")

        org_id = d.pop("org_id", UNSET)

        exposure_layer_request = cls(
            asset_ref=asset_ref,
            exposure_layer=exposure_layer,
            org_id=org_id,
        )

        exposure_layer_request.additional_properties = d
        return exposure_layer_request

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
