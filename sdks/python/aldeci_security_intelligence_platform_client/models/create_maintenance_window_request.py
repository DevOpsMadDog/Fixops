from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.change_risk_level import ChangeRiskLevel
from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateMaintenanceWindowRequest")


@_attrs_define
class CreateMaintenanceWindowRequest:
    """
    Attributes:
        name (str):
        start_time (datetime.datetime):
        end_time (datetime.datetime):
        description (None | str | Unset):
        allowed_risk_levels (list[ChangeRiskLevel] | Unset):
        recurring (bool | Unset):  Default: False.
        recurrence_days (int | None | Unset):
    """

    name: str
    start_time: datetime.datetime
    end_time: datetime.datetime
    description: None | str | Unset = UNSET
    allowed_risk_levels: list[ChangeRiskLevel] | Unset = UNSET
    recurring: bool | Unset = False
    recurrence_days: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        start_time = self.start_time.isoformat()

        end_time = self.end_time.isoformat()

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        allowed_risk_levels: list[str] | Unset = UNSET
        if not isinstance(self.allowed_risk_levels, Unset):
            allowed_risk_levels = []
            for allowed_risk_levels_item_data in self.allowed_risk_levels:
                allowed_risk_levels_item = allowed_risk_levels_item_data.value
                allowed_risk_levels.append(allowed_risk_levels_item)

        recurring = self.recurring

        recurrence_days: int | None | Unset
        if isinstance(self.recurrence_days, Unset):
            recurrence_days = UNSET
        else:
            recurrence_days = self.recurrence_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "start_time": start_time,
                "end_time": end_time,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if allowed_risk_levels is not UNSET:
            field_dict["allowed_risk_levels"] = allowed_risk_levels
        if recurring is not UNSET:
            field_dict["recurring"] = recurring
        if recurrence_days is not UNSET:
            field_dict["recurrence_days"] = recurrence_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        start_time = isoparse(d.pop("start_time"))

        end_time = isoparse(d.pop("end_time"))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        _allowed_risk_levels = d.pop("allowed_risk_levels", UNSET)
        allowed_risk_levels: list[ChangeRiskLevel] | Unset = UNSET
        if _allowed_risk_levels is not UNSET:
            allowed_risk_levels = []
            for allowed_risk_levels_item_data in _allowed_risk_levels:
                allowed_risk_levels_item = ChangeRiskLevel(allowed_risk_levels_item_data)

                allowed_risk_levels.append(allowed_risk_levels_item)

        recurring = d.pop("recurring", UNSET)

        def _parse_recurrence_days(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        recurrence_days = _parse_recurrence_days(d.pop("recurrence_days", UNSET))

        create_maintenance_window_request = cls(
            name=name,
            start_time=start_time,
            end_time=end_time,
            description=description,
            allowed_risk_levels=allowed_risk_levels,
            recurring=recurring,
            recurrence_days=recurrence_days,
        )

        create_maintenance_window_request.additional_properties = d
        return create_maintenance_window_request

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
