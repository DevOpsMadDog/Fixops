from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.activity_record_details import ActivityRecordDetails


T = TypeVar("T", bound="ActivityRecord")


@_attrs_define
class ActivityRecord:
    """A single recorded user-activity event.

    Attributes:
        user_email (str):
        activity_type (str):
        org_id (str):
        id (str | Unset):
        details (ActivityRecordDetails | Unset):
        recorded_at (datetime.datetime | Unset):
        acknowledged (bool | Unset):  Default: False.
        acknowledged_by (None | str | Unset):
        acknowledged_at (datetime.datetime | None | Unset):
    """

    user_email: str
    activity_type: str
    org_id: str
    id: str | Unset = UNSET
    details: ActivityRecordDetails | Unset = UNSET
    recorded_at: datetime.datetime | Unset = UNSET
    acknowledged: bool | Unset = False
    acknowledged_by: None | str | Unset = UNSET
    acknowledged_at: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_email = self.user_email

        activity_type = self.activity_type

        org_id = self.org_id

        id = self.id

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        recorded_at: str | Unset = UNSET
        if not isinstance(self.recorded_at, Unset):
            recorded_at = self.recorded_at.isoformat()

        acknowledged = self.acknowledged

        acknowledged_by: None | str | Unset
        if isinstance(self.acknowledged_by, Unset):
            acknowledged_by = UNSET
        else:
            acknowledged_by = self.acknowledged_by

        acknowledged_at: None | str | Unset
        if isinstance(self.acknowledged_at, Unset):
            acknowledged_at = UNSET
        elif isinstance(self.acknowledged_at, datetime.datetime):
            acknowledged_at = self.acknowledged_at.isoformat()
        else:
            acknowledged_at = self.acknowledged_at

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
        if details is not UNSET:
            field_dict["details"] = details
        if recorded_at is not UNSET:
            field_dict["recorded_at"] = recorded_at
        if acknowledged is not UNSET:
            field_dict["acknowledged"] = acknowledged
        if acknowledged_by is not UNSET:
            field_dict["acknowledged_by"] = acknowledged_by
        if acknowledged_at is not UNSET:
            field_dict["acknowledged_at"] = acknowledged_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.activity_record_details import ActivityRecordDetails

        d = dict(src_dict)
        user_email = d.pop("user_email")

        activity_type = d.pop("activity_type")

        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        _details = d.pop("details", UNSET)
        details: ActivityRecordDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = ActivityRecordDetails.from_dict(_details)

        _recorded_at = d.pop("recorded_at", UNSET)
        recorded_at: datetime.datetime | Unset
        if isinstance(_recorded_at, Unset):
            recorded_at = UNSET
        else:
            recorded_at = isoparse(_recorded_at)

        acknowledged = d.pop("acknowledged", UNSET)

        def _parse_acknowledged_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        acknowledged_by = _parse_acknowledged_by(d.pop("acknowledged_by", UNSET))

        def _parse_acknowledged_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                acknowledged_at_type_0 = isoparse(data)

                return acknowledged_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        acknowledged_at = _parse_acknowledged_at(d.pop("acknowledged_at", UNSET))

        activity_record = cls(
            user_email=user_email,
            activity_type=activity_type,
            org_id=org_id,
            id=id,
            details=details,
            recorded_at=recorded_at,
            acknowledged=acknowledged,
            acknowledged_by=acknowledged_by,
            acknowledged_at=acknowledged_at,
        )

        activity_record.additional_properties = d
        return activity_record

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
