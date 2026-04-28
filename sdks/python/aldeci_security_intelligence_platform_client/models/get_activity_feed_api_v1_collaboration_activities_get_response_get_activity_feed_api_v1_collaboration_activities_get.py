from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar(
    "T", bound="GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet"
)


@_attrs_define
class GetActivityFeedApiV1CollaborationActivitiesGetResponseGetActivityFeedApiV1CollaborationActivitiesGet:
    """ """

    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        get_activity_feed_api_v1_collaboration_activities_get_response_get_activity_feed_api_v1_collaboration_activities_get = cls()

        get_activity_feed_api_v1_collaboration_activities_get_response_get_activity_feed_api_v1_collaboration_activities_get.additional_properties = d
        return get_activity_feed_api_v1_collaboration_activities_get_response_get_activity_feed_api_v1_collaboration_activities_get

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
