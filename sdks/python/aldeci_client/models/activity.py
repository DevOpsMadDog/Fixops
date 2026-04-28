from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.activity_type import ActivityType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.activity_metadata import ActivityMetadata


T = TypeVar("T", bound="Activity")


@_attrs_define
class Activity:
    """A single recorded user activity event.

    Attributes:
        user_email (str):
        activity_type (ActivityType): Types of user activity events.
        org_id (str):
        id (str | Unset):
        endpoint (None | str | Unset):
        feature (None | str | Unset):
        metadata (ActivityMetadata | Unset):
        ip_address (str | Unset):  Default: ''.
        timestamp (datetime.datetime | Unset):
    """

    user_email: str
    activity_type: ActivityType
    org_id: str
    id: str | Unset = UNSET
    endpoint: None | str | Unset = UNSET
    feature: None | str | Unset = UNSET
    metadata: ActivityMetadata | Unset = UNSET
    ip_address: str | Unset = ""
    timestamp: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_email = self.user_email

        activity_type = self.activity_type.value

        org_id = self.org_id

        id = self.id

        endpoint: None | str | Unset
        if isinstance(self.endpoint, Unset):
            endpoint = UNSET
        else:
            endpoint = self.endpoint

        feature: None | str | Unset
        if isinstance(self.feature, Unset):
            feature = UNSET
        else:
            feature = self.feature

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        ip_address = self.ip_address

        timestamp: str | Unset = UNSET
        if not isinstance(self.timestamp, Unset):
            timestamp = self.timestamp.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_email": user_email,
                "activity_type": activity_type,
                "org_id": org_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if endpoint is not UNSET:
            field_dict["endpoint"] = endpoint
        if feature is not UNSET:
            field_dict["feature"] = feature
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if timestamp is not UNSET:
            field_dict["timestamp"] = timestamp

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.activity_metadata import ActivityMetadata

        d = dict(src_dict)
        user_email = d.pop("user_email")

        activity_type = ActivityType(d.pop("activity_type"))

        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        def _parse_endpoint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        endpoint = _parse_endpoint(d.pop("endpoint", UNSET))

        def _parse_feature(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        feature = _parse_feature(d.pop("feature", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: ActivityMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = ActivityMetadata.from_dict(_metadata)

        ip_address = d.pop("ip_address", UNSET)

        _timestamp = d.pop("timestamp", UNSET)
        timestamp: datetime.datetime | Unset
        if isinstance(_timestamp, Unset):
            timestamp = UNSET
        else:
            timestamp = isoparse(_timestamp)

        activity = cls(
            user_email=user_email,
            activity_type=activity_type,
            org_id=org_id,
            id=id,
            endpoint=endpoint,
            feature=feature,
            metadata=metadata,
            ip_address=ip_address,
            timestamp=timestamp,
        )

        activity.additional_properties = d
        return activity

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
