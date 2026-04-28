from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DataAssetReq")


@_attrs_define
class DataAssetReq:
    """
    Attributes:
        org_id (str):
        name (str):
        data_category (str):
        classification (str | Unset):  Default: 'internal'.
        description (None | str | Unset):
        location (None | str | Unset):
        data_owner (None | str | Unset):
        retention_days (int | None | Unset):
    """

    org_id: str
    name: str
    data_category: str
    classification: str | Unset = "internal"
    description: None | str | Unset = UNSET
    location: None | str | Unset = UNSET
    data_owner: None | str | Unset = UNSET
    retention_days: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        name = self.name

        data_category = self.data_category

        classification = self.classification

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        location: None | str | Unset
        if isinstance(self.location, Unset):
            location = UNSET
        else:
            location = self.location

        data_owner: None | str | Unset
        if isinstance(self.data_owner, Unset):
            data_owner = UNSET
        else:
            data_owner = self.data_owner

        retention_days: int | None | Unset
        if isinstance(self.retention_days, Unset):
            retention_days = UNSET
        else:
            retention_days = self.retention_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "name": name,
                "data_category": data_category,
            }
        )
        if classification is not UNSET:
            field_dict["classification"] = classification
        if description is not UNSET:
            field_dict["description"] = description
        if location is not UNSET:
            field_dict["location"] = location
        if data_owner is not UNSET:
            field_dict["data_owner"] = data_owner
        if retention_days is not UNSET:
            field_dict["retention_days"] = retention_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        name = d.pop("name")

        data_category = d.pop("data_category")

        classification = d.pop("classification", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_location(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        location = _parse_location(d.pop("location", UNSET))

        def _parse_data_owner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        data_owner = _parse_data_owner(d.pop("data_owner", UNSET))

        def _parse_retention_days(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        retention_days = _parse_retention_days(d.pop("retention_days", UNSET))

        data_asset_req = cls(
            org_id=org_id,
            name=name,
            data_category=data_category,
            classification=classification,
            description=description,
            location=location,
            data_owner=data_owner,
            retention_days=retention_days,
        )

        data_asset_req.additional_properties = d
        return data_asset_req

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
