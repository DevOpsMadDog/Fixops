from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssetCreate")


@_attrs_define
class AssetCreate:
    """
    Attributes:
        asset_name (str):
        asset_type (str):
        owner (str | Unset):  Default: ''.
        business_function (str | Unset):  Default: ''.
        data_classification (str | Unset):  Default: 'internal'.
        availability_requirement (str | Unset):  Default: 'medium'.
        integrity_requirement (str | Unset):  Default: 'medium'.
        confidentiality_requirement (str | Unset):  Default: 'medium'.
    """

    asset_name: str
    asset_type: str
    owner: str | Unset = ""
    business_function: str | Unset = ""
    data_classification: str | Unset = "internal"
    availability_requirement: str | Unset = "medium"
    integrity_requirement: str | Unset = "medium"
    confidentiality_requirement: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_name = self.asset_name

        asset_type = self.asset_type

        owner = self.owner

        business_function = self.business_function

        data_classification = self.data_classification

        availability_requirement = self.availability_requirement

        integrity_requirement = self.integrity_requirement

        confidentiality_requirement = self.confidentiality_requirement

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_name": asset_name,
                "asset_type": asset_type,
            }
        )
        if owner is not UNSET:
            field_dict["owner"] = owner
        if business_function is not UNSET:
            field_dict["business_function"] = business_function
        if data_classification is not UNSET:
            field_dict["data_classification"] = data_classification
        if availability_requirement is not UNSET:
            field_dict["availability_requirement"] = availability_requirement
        if integrity_requirement is not UNSET:
            field_dict["integrity_requirement"] = integrity_requirement
        if confidentiality_requirement is not UNSET:
            field_dict["confidentiality_requirement"] = confidentiality_requirement

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_name = d.pop("asset_name")

        asset_type = d.pop("asset_type")

        owner = d.pop("owner", UNSET)

        business_function = d.pop("business_function", UNSET)

        data_classification = d.pop("data_classification", UNSET)

        availability_requirement = d.pop("availability_requirement", UNSET)

        integrity_requirement = d.pop("integrity_requirement", UNSET)

        confidentiality_requirement = d.pop("confidentiality_requirement", UNSET)

        asset_create = cls(
            asset_name=asset_name,
            asset_type=asset_type,
            owner=owner,
            business_function=business_function,
            data_classification=data_classification,
            availability_requirement=availability_requirement,
            integrity_requirement=integrity_requirement,
            confidentiality_requirement=confidentiality_requirement,
        )

        asset_create.additional_properties = d
        return asset_create

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
