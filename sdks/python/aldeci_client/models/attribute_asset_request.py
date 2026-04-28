from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AttributeAssetRequest")


@_attrs_define
class AttributeAssetRequest:
    """
    Attributes:
        asset_ref (str): Opaque reference to the asset (e.g. domain, ID)
        subsidiary_name (str): Subsidiary / business-unit name
        attribution_source (str): Source of attribution: manual / whois / registration / heuristic
        org_id (str | Unset): Organisation ID Default: 'default'.
        confidence (float | Unset): Attribution confidence (0-1) Default: 0.5.
    """

    asset_ref: str
    subsidiary_name: str
    attribution_source: str
    org_id: str | Unset = "default"
    confidence: float | Unset = 0.5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_ref = self.asset_ref

        subsidiary_name = self.subsidiary_name

        attribution_source = self.attribution_source

        org_id = self.org_id

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_ref": asset_ref,
                "subsidiary_name": subsidiary_name,
                "attribution_source": attribution_source,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if confidence is not UNSET:
            field_dict["confidence"] = confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_ref = d.pop("asset_ref")

        subsidiary_name = d.pop("subsidiary_name")

        attribution_source = d.pop("attribution_source")

        org_id = d.pop("org_id", UNSET)

        confidence = d.pop("confidence", UNSET)

        attribute_asset_request = cls(
            asset_ref=asset_ref,
            subsidiary_name=subsidiary_name,
            attribution_source=attribution_source,
            org_id=org_id,
            confidence=confidence,
        )

        attribute_asset_request.additional_properties = d
        return attribute_asset_request

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
