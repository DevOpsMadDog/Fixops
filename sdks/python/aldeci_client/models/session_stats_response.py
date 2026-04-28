from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.session_stats_response_by_user import SessionStatsResponseByUser


T = TypeVar("T", bound="SessionStatsResponse")


@_attrs_define
class SessionStatsResponse:
    """Session statistics for an org.

    Attributes:
        org_id (str):
        active_count (int):
        avg_duration_seconds (float):
        by_user (SessionStatsResponseByUser):
    """

    org_id: str
    active_count: int
    avg_duration_seconds: float
    by_user: SessionStatsResponseByUser
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        active_count = self.active_count

        avg_duration_seconds = self.avg_duration_seconds

        by_user = self.by_user.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "active_count": active_count,
                "avg_duration_seconds": avg_duration_seconds,
                "by_user": by_user,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.session_stats_response_by_user import SessionStatsResponseByUser

        d = dict(src_dict)
        org_id = d.pop("org_id")

        active_count = d.pop("active_count")

        avg_duration_seconds = d.pop("avg_duration_seconds")

        by_user = SessionStatsResponseByUser.from_dict(d.pop("by_user"))

        session_stats_response = cls(
            org_id=org_id,
            active_count=active_count,
            avg_duration_seconds=avg_duration_seconds,
            by_user=by_user,
        )

        session_stats_response.additional_properties = d
        return session_stats_response

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
