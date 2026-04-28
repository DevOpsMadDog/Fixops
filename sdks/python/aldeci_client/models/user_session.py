from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="UserSession")


@_attrs_define
class UserSession:
    """Aggregated session record for a user within a time window.

    Attributes:
        user_email (str):
        started_at (datetime.datetime):
        last_active (datetime.datetime):
        duration_minutes (float):
        activity_count (int):
        org_id (str):
        id (str | Unset):
    """

    user_email: str
    started_at: datetime.datetime
    last_active: datetime.datetime
    duration_minutes: float
    activity_count: int
    org_id: str
    id: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_email = self.user_email

        started_at = self.started_at.isoformat()

        last_active = self.last_active.isoformat()

        duration_minutes = self.duration_minutes

        activity_count = self.activity_count

        org_id = self.org_id

        id = self.id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_email": user_email,
                "started_at": started_at,
                "last_active": last_active,
                "duration_minutes": duration_minutes,
                "activity_count": activity_count,
                "org_id": org_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_email = d.pop("user_email")

        started_at = isoparse(d.pop("started_at"))

        last_active = isoparse(d.pop("last_active"))

        duration_minutes = d.pop("duration_minutes")

        activity_count = d.pop("activity_count")

        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        user_session = cls(
            user_email=user_email,
            started_at=started_at,
            last_active=last_active,
            duration_minutes=duration_minutes,
            activity_count=activity_count,
            org_id=org_id,
            id=id,
        )

        user_session.additional_properties = d
        return user_session

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
