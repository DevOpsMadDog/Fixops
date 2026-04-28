from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateIncidentRequest")


@_attrs_define
class UpdateIncidentRequest:
    """Request body for updating a PagerDuty incident.

    Attributes:
        status (None | str | Unset): New status: 'acknowledged' or 'resolved'
        title (None | str | Unset): New incident title
        urgency (None | str | Unset): New urgency: 'high' or 'low'
        resolution (None | str | Unset): Resolution note
    """

    status: None | str | Unset = UNSET
    title: None | str | Unset = UNSET
    urgency: None | str | Unset = UNSET
    resolution: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        title: None | str | Unset
        if isinstance(self.title, Unset):
            title = UNSET
        else:
            title = self.title

        urgency: None | str | Unset
        if isinstance(self.urgency, Unset):
            urgency = UNSET
        else:
            urgency = self.urgency

        resolution: None | str | Unset
        if isinstance(self.resolution, Unset):
            resolution = UNSET
        else:
            resolution = self.resolution

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if status is not UNSET:
            field_dict["status"] = status
        if title is not UNSET:
            field_dict["title"] = title
        if urgency is not UNSET:
            field_dict["urgency"] = urgency
        if resolution is not UNSET:
            field_dict["resolution"] = resolution

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        title = _parse_title(d.pop("title", UNSET))

        def _parse_urgency(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        urgency = _parse_urgency(d.pop("urgency", UNSET))

        def _parse_resolution(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        resolution = _parse_resolution(d.pop("resolution", UNSET))

        update_incident_request = cls(
            status=status,
            title=title,
            urgency=urgency,
            resolution=resolution,
        )

        update_incident_request.additional_properties = d
        return update_incident_request

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
