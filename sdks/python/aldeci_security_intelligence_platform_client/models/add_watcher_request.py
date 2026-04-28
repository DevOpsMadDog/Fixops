from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddWatcherRequest")


@_attrs_define
class AddWatcherRequest:
    """Request to add a watcher.

    Attributes:
        entity_type (str):
        entity_id (str):
        user_id (str):
        user_email (None | str | Unset):
        added_by (None | str | Unset):
    """

    entity_type: str
    entity_id: str
    user_id: str
    user_email: None | str | Unset = UNSET
    added_by: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_type = self.entity_type

        entity_id = self.entity_id

        user_id = self.user_id

        user_email: None | str | Unset
        if isinstance(self.user_email, Unset):
            user_email = UNSET
        else:
            user_email = self.user_email

        added_by: None | str | Unset
        if isinstance(self.added_by, Unset):
            added_by = UNSET
        else:
            added_by = self.added_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "user_id": user_id,
            }
        )
        if user_email is not UNSET:
            field_dict["user_email"] = user_email
        if added_by is not UNSET:
            field_dict["added_by"] = added_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        entity_type = d.pop("entity_type")

        entity_id = d.pop("entity_id")

        user_id = d.pop("user_id")

        def _parse_user_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        user_email = _parse_user_email(d.pop("user_email", UNSET))

        def _parse_added_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        added_by = _parse_added_by(d.pop("added_by", UNSET))

        add_watcher_request = cls(
            entity_type=entity_type,
            entity_id=entity_id,
            user_id=user_id,
            user_email=user_email,
            added_by=added_by,
        )

        add_watcher_request.additional_properties = d
        return add_watcher_request

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
