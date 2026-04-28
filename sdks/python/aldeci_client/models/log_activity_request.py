from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LogActivityRequest")


@_attrs_define
class LogActivityRequest:
    """Request to log a security activity for neglect zone tracking.

    Attributes:
        org_id (str): Organisation identifier
        component (str): Component / service name
        activity_type (str): Type of activity: scan, review, drill, pentest, audit
        description (str | Unset): Activity description Default: ''.
        actor (None | str | Unset): Who performed the activity
        has_critical_data (bool | Unset): Does this component hold critical data? Default: False.
    """

    org_id: str
    component: str
    activity_type: str
    description: str | Unset = ""
    actor: None | str | Unset = UNSET
    has_critical_data: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        component = self.component

        activity_type = self.activity_type

        description = self.description

        actor: None | str | Unset
        if isinstance(self.actor, Unset):
            actor = UNSET
        else:
            actor = self.actor

        has_critical_data = self.has_critical_data

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "component": component,
                "activity_type": activity_type,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if actor is not UNSET:
            field_dict["actor"] = actor
        if has_critical_data is not UNSET:
            field_dict["has_critical_data"] = has_critical_data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        component = d.pop("component")

        activity_type = d.pop("activity_type")

        description = d.pop("description", UNSET)

        def _parse_actor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        actor = _parse_actor(d.pop("actor", UNSET))

        has_critical_data = d.pop("has_critical_data", UNSET)

        log_activity_request = cls(
            org_id=org_id,
            component=component,
            activity_type=activity_type,
            description=description,
            actor=actor,
            has_critical_data=has_critical_data,
        )

        log_activity_request.additional_properties = d
        return log_activity_request

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
