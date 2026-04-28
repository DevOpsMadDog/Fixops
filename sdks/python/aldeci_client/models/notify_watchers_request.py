from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.notify_watchers_request_metadata_type_0 import NotifyWatchersRequestMetadataType0


T = TypeVar("T", bound="NotifyWatchersRequest")


@_attrs_define
class NotifyWatchersRequest:
    """Request to notify all watchers of an entity.

    Attributes:
        entity_type (str):
        entity_id (str):
        notification_type (str):
        title (str):
        message (str):
        priority (str | Unset):  Default: 'normal'.
        metadata (None | NotifyWatchersRequestMetadataType0 | Unset):
        exclude_users (list[str] | None | Unset):
    """

    entity_type: str
    entity_id: str
    notification_type: str
    title: str
    message: str
    priority: str | Unset = "normal"
    metadata: None | NotifyWatchersRequestMetadataType0 | Unset = UNSET
    exclude_users: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.notify_watchers_request_metadata_type_0 import NotifyWatchersRequestMetadataType0

        entity_type = self.entity_type

        entity_id = self.entity_id

        notification_type = self.notification_type

        title = self.title

        message = self.message

        priority = self.priority

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, NotifyWatchersRequestMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        exclude_users: list[str] | None | Unset
        if isinstance(self.exclude_users, Unset):
            exclude_users = UNSET
        elif isinstance(self.exclude_users, list):
            exclude_users = self.exclude_users

        else:
            exclude_users = self.exclude_users

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "notification_type": notification_type,
                "title": title,
                "message": message,
            }
        )
        if priority is not UNSET:
            field_dict["priority"] = priority
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if exclude_users is not UNSET:
            field_dict["exclude_users"] = exclude_users

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.notify_watchers_request_metadata_type_0 import NotifyWatchersRequestMetadataType0

        d = dict(src_dict)
        entity_type = d.pop("entity_type")

        entity_id = d.pop("entity_id")

        notification_type = d.pop("notification_type")

        title = d.pop("title")

        message = d.pop("message")

        priority = d.pop("priority", UNSET)

        def _parse_metadata(data: object) -> None | NotifyWatchersRequestMetadataType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = NotifyWatchersRequestMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | NotifyWatchersRequestMetadataType0 | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        def _parse_exclude_users(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                exclude_users_type_0 = cast(list[str], data)

                return exclude_users_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        exclude_users = _parse_exclude_users(d.pop("exclude_users", UNSET))

        notify_watchers_request = cls(
            entity_type=entity_type,
            entity_id=entity_id,
            notification_type=notification_type,
            title=title,
            message=message,
            priority=priority,
            metadata=metadata,
            exclude_users=exclude_users,
        )

        notify_watchers_request.additional_properties = d
        return notify_watchers_request

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
