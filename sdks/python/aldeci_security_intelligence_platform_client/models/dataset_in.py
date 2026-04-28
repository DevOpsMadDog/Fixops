from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DatasetIn")


@_attrs_define
class DatasetIn:
    """
    Attributes:
        dataset_name (str | Unset):  Default: ''.
        policy_id (str | Unset):  Default: ''.
        location (str | Unset):  Default: ''.
        size_bytes (int | Unset):  Default: 0.
        record_count (int | Unset):  Default: 0.
        created_at (None | str | Unset):
        data_owner (str | Unset):  Default: ''.
    """

    dataset_name: str | Unset = ""
    policy_id: str | Unset = ""
    location: str | Unset = ""
    size_bytes: int | Unset = 0
    record_count: int | Unset = 0
    created_at: None | str | Unset = UNSET
    data_owner: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dataset_name = self.dataset_name

        policy_id = self.policy_id

        location = self.location

        size_bytes = self.size_bytes

        record_count = self.record_count

        created_at: None | str | Unset
        if isinstance(self.created_at, Unset):
            created_at = UNSET
        else:
            created_at = self.created_at

        data_owner = self.data_owner

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if dataset_name is not UNSET:
            field_dict["dataset_name"] = dataset_name
        if policy_id is not UNSET:
            field_dict["policy_id"] = policy_id
        if location is not UNSET:
            field_dict["location"] = location
        if size_bytes is not UNSET:
            field_dict["size_bytes"] = size_bytes
        if record_count is not UNSET:
            field_dict["record_count"] = record_count
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if data_owner is not UNSET:
            field_dict["data_owner"] = data_owner

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        dataset_name = d.pop("dataset_name", UNSET)

        policy_id = d.pop("policy_id", UNSET)

        location = d.pop("location", UNSET)

        size_bytes = d.pop("size_bytes", UNSET)

        record_count = d.pop("record_count", UNSET)

        def _parse_created_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created_at = _parse_created_at(d.pop("created_at", UNSET))

        data_owner = d.pop("data_owner", UNSET)

        dataset_in = cls(
            dataset_name=dataset_name,
            policy_id=policy_id,
            location=location,
            size_bytes=size_bytes,
            record_count=record_count,
            created_at=created_at,
            data_owner=data_owner,
        )

        dataset_in.additional_properties = d
        return dataset_in

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
