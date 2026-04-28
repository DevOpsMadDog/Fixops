from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatastoreCreate")


@_attrs_define
class DatastoreCreate:
    """
    Attributes:
        name (str):
        datastore_type (str | Unset):  Default: 'database'.
        location (str | Unset):  Default: ''.
        owner_team (str | Unset):  Default: ''.
        data_types_found (list[str] | Unset):
        risk_level (str | Unset):  Default: 'none'.
        record_count (int | Unset):  Default: 0.
    """

    name: str
    datastore_type: str | Unset = "database"
    location: str | Unset = ""
    owner_team: str | Unset = ""
    data_types_found: list[str] | Unset = UNSET
    risk_level: str | Unset = "none"
    record_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        datastore_type = self.datastore_type

        location = self.location

        owner_team = self.owner_team

        data_types_found: list[str] | Unset = UNSET
        if not isinstance(self.data_types_found, Unset):
            data_types_found = self.data_types_found

        risk_level = self.risk_level

        record_count = self.record_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if datastore_type is not UNSET:
            field_dict["datastore_type"] = datastore_type
        if location is not UNSET:
            field_dict["location"] = location
        if owner_team is not UNSET:
            field_dict["owner_team"] = owner_team
        if data_types_found is not UNSET:
            field_dict["data_types_found"] = data_types_found
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if record_count is not UNSET:
            field_dict["record_count"] = record_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        datastore_type = d.pop("datastore_type", UNSET)

        location = d.pop("location", UNSET)

        owner_team = d.pop("owner_team", UNSET)

        data_types_found = cast(list[str], d.pop("data_types_found", UNSET))

        risk_level = d.pop("risk_level", UNSET)

        record_count = d.pop("record_count", UNSET)

        datastore_create = cls(
            name=name,
            datastore_type=datastore_type,
            location=location,
            owner_team=owner_team,
            data_types_found=data_types_found,
            risk_level=risk_level,
            record_count=record_count,
        )

        datastore_create.additional_properties = d
        return datastore_create

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
