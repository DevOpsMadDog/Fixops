from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DataStoreCreate")


@_attrs_define
class DataStoreCreate:
    """
    Attributes:
        name (str):
        org_id (str | Unset):  Default: 'default'.
        store_type (str | Unset):  Default: 's3'.
        classification (str | Unset):  Default: 'internal'.
        encryption_at_rest (bool | Unset):  Default: True.
        access_logging (bool | Unset):  Default: True.
    """

    name: str
    org_id: str | Unset = "default"
    store_type: str | Unset = "s3"
    classification: str | Unset = "internal"
    encryption_at_rest: bool | Unset = True
    access_logging: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        org_id = self.org_id

        store_type = self.store_type

        classification = self.classification

        encryption_at_rest = self.encryption_at_rest

        access_logging = self.access_logging

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if store_type is not UNSET:
            field_dict["store_type"] = store_type
        if classification is not UNSET:
            field_dict["classification"] = classification
        if encryption_at_rest is not UNSET:
            field_dict["encryption_at_rest"] = encryption_at_rest
        if access_logging is not UNSET:
            field_dict["access_logging"] = access_logging

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        org_id = d.pop("org_id", UNSET)

        store_type = d.pop("store_type", UNSET)

        classification = d.pop("classification", UNSET)

        encryption_at_rest = d.pop("encryption_at_rest", UNSET)

        access_logging = d.pop("access_logging", UNSET)

        data_store_create = cls(
            name=name,
            org_id=org_id,
            store_type=store_type,
            classification=classification,
            encryption_at_rest=encryption_at_rest,
            access_logging=access_logging,
        )

        data_store_create.additional_properties = d
        return data_store_create

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
