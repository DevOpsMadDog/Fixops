from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BaselineUpsert")


@_attrs_define
class BaselineUpsert:
    """
    Attributes:
        org_id (str):
        username (str):
        typical_countries (list[str] | Unset):
        typical_hours (list[int] | Unset):
        typical_resources (list[str] | Unset):
        avg_daily_events (float | Unset):  Default: 0.0.
    """

    org_id: str
    username: str
    typical_countries: list[str] | Unset = UNSET
    typical_hours: list[int] | Unset = UNSET
    typical_resources: list[str] | Unset = UNSET
    avg_daily_events: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        username = self.username

        typical_countries: list[str] | Unset = UNSET
        if not isinstance(self.typical_countries, Unset):
            typical_countries = self.typical_countries

        typical_hours: list[int] | Unset = UNSET
        if not isinstance(self.typical_hours, Unset):
            typical_hours = self.typical_hours

        typical_resources: list[str] | Unset = UNSET
        if not isinstance(self.typical_resources, Unset):
            typical_resources = self.typical_resources

        avg_daily_events = self.avg_daily_events

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "username": username,
            }
        )
        if typical_countries is not UNSET:
            field_dict["typical_countries"] = typical_countries
        if typical_hours is not UNSET:
            field_dict["typical_hours"] = typical_hours
        if typical_resources is not UNSET:
            field_dict["typical_resources"] = typical_resources
        if avg_daily_events is not UNSET:
            field_dict["avg_daily_events"] = avg_daily_events

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        username = d.pop("username")

        typical_countries = cast(list[str], d.pop("typical_countries", UNSET))

        typical_hours = cast(list[int], d.pop("typical_hours", UNSET))

        typical_resources = cast(list[str], d.pop("typical_resources", UNSET))

        avg_daily_events = d.pop("avg_daily_events", UNSET)

        baseline_upsert = cls(
            org_id=org_id,
            username=username,
            typical_countries=typical_countries,
            typical_hours=typical_hours,
            typical_resources=typical_resources,
            avg_daily_events=avg_daily_events,
        )

        baseline_upsert.additional_properties = d
        return baseline_upsert

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
