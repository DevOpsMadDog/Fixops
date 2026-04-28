from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ActivityCreate")


@_attrs_define
class ActivityCreate:
    """
    Attributes:
        activity_type (str | Unset):  Default: 'training'.
        points_awarded (int | None | Unset):
        description (str | Unset):  Default: ''.
        completed_at (None | str | Unset):
        verified_by (str | Unset):  Default: ''.
    """

    activity_type: str | Unset = "training"
    points_awarded: int | None | Unset = UNSET
    description: str | Unset = ""
    completed_at: None | str | Unset = UNSET
    verified_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        activity_type = self.activity_type

        points_awarded: int | None | Unset
        if isinstance(self.points_awarded, Unset):
            points_awarded = UNSET
        else:
            points_awarded = self.points_awarded

        description = self.description

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        else:
            completed_at = self.completed_at

        verified_by = self.verified_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if activity_type is not UNSET:
            field_dict["activity_type"] = activity_type
        if points_awarded is not UNSET:
            field_dict["points_awarded"] = points_awarded
        if description is not UNSET:
            field_dict["description"] = description
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if verified_by is not UNSET:
            field_dict["verified_by"] = verified_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        activity_type = d.pop("activity_type", UNSET)

        def _parse_points_awarded(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        points_awarded = _parse_points_awarded(d.pop("points_awarded", UNSET))

        description = d.pop("description", UNSET)

        def _parse_completed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        verified_by = d.pop("verified_by", UNSET)

        activity_create = cls(
            activity_type=activity_type,
            points_awarded=points_awarded,
            description=description,
            completed_at=completed_at,
            verified_by=verified_by,
        )

        activity_create.additional_properties = d
        return activity_create

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
