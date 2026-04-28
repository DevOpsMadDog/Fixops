from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.queue_notification_request_metadata_type_0 import QueueNotificationRequestMetadataType0


T = TypeVar("T", bound="QueueNotificationRequest")


@_attrs_define
class QueueNotificationRequest:
    """Request to queue a notification.

    Attributes:
        entity_type (str):
        entity_id (str):
        notification_type (str):
        title (str):
        message (str):
        recipients (list[str]):
        priority (str | Unset):  Default: 'normal'.
        metadata (None | QueueNotificationRequestMetadataType0 | Unset):
    """

    entity_type: str
    entity_id: str
    notification_type: str
    title: str
    message: str
    recipients: list[str]
    priority: str | Unset = "normal"
    metadata: None | QueueNotificationRequestMetadataType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.queue_notification_request_metadata_type_0 import QueueNotificationRequestMetadataType0

        entity_type = self.entity_type

        entity_id = self.entity_id

        notification_type = self.notification_type

        title = self.title

        message = self.message

        recipients = self.recipients

        priority = self.priority

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, QueueNotificationRequestMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "notification_type": notification_type,
                "title": title,
                "message": message,
                "recipients": recipients,
            }
        )
        if priority is not UNSET:
            field_dict["priority"] = priority
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.queue_notification_request_metadata_type_0 import QueueNotificationRequestMetadataType0

        d = dict(src_dict)
        entity_type = d.pop("entity_type")

        entity_id = d.pop("entity_id")

        notification_type = d.pop("notification_type")

        title = d.pop("title")

        message = d.pop("message")

        recipients = cast(list[str], d.pop("recipients"))

        priority = d.pop("priority", UNSET)

        def _parse_metadata(data: object) -> None | QueueNotificationRequestMetadataType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = QueueNotificationRequestMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | QueueNotificationRequestMetadataType0 | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        queue_notification_request = cls(
            entity_type=entity_type,
            entity_id=entity_id,
            notification_type=notification_type,
            title=title,
            message=message,
            recipients=recipients,
            priority=priority,
            metadata=metadata,
        )

        queue_notification_request.additional_properties = d
        return queue_notification_request

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
