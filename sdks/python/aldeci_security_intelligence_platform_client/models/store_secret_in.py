from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="StoreSecretIn")


@_attrs_define
class StoreSecretIn:
    """
    Attributes:
        name (str): Human-readable secret name
        secret_type (str | Unset): api_key|password|certificate|token|ssh_key|database Default: 'api_key'.
        path (str | Unset): Vault path or location reference Default: ''.
        tags (list[str] | Unset): Arbitrary tags
        rotation_days (int | Unset): Rotation interval in days Default: 90.
    """

    name: str
    secret_type: str | Unset = "api_key"
    path: str | Unset = ""
    tags: list[str] | Unset = UNSET
    rotation_days: int | Unset = 90
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        secret_type = self.secret_type

        path = self.path

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        rotation_days = self.rotation_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if secret_type is not UNSET:
            field_dict["secret_type"] = secret_type
        if path is not UNSET:
            field_dict["path"] = path
        if tags is not UNSET:
            field_dict["tags"] = tags
        if rotation_days is not UNSET:
            field_dict["rotation_days"] = rotation_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        secret_type = d.pop("secret_type", UNSET)

        path = d.pop("path", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        rotation_days = d.pop("rotation_days", UNSET)

        store_secret_in = cls(
            name=name,
            secret_type=secret_type,
            path=path,
            tags=tags,
            rotation_days=rotation_days,
        )

        store_secret_in.additional_properties = d
        return store_secret_in

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
