from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="KeyResultAdd")


@_attrs_define
class KeyResultAdd:
    """Request body for adding a key result.

    Attributes:
        title (str):
        target_value (float): Goal value to reach
        current_value (float | Unset): Current measured value Default: 0.0.
        unit (str | Unset): Unit of measurement Default: '%'.
        due_date (datetime.date | None | Unset):
    """

    title: str
    target_value: float
    current_value: float | Unset = 0.0
    unit: str | Unset = "%"
    due_date: datetime.date | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        target_value = self.target_value

        current_value = self.current_value

        unit = self.unit

        due_date: None | str | Unset
        if isinstance(self.due_date, Unset):
            due_date = UNSET
        elif isinstance(self.due_date, datetime.date):
            due_date = self.due_date.isoformat()
        else:
            due_date = self.due_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "target_value": target_value,
            }
        )
        if current_value is not UNSET:
            field_dict["current_value"] = current_value
        if unit is not UNSET:
            field_dict["unit"] = unit
        if due_date is not UNSET:
            field_dict["due_date"] = due_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        target_value = d.pop("target_value")

        current_value = d.pop("current_value", UNSET)

        unit = d.pop("unit", UNSET)

        def _parse_due_date(data: object) -> datetime.date | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                due_date_type_0 = isoparse(data).date()

                return due_date_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.date | None | Unset, data)

        due_date = _parse_due_date(d.pop("due_date", UNSET))

        key_result_add = cls(
            title=title,
            target_value=target_value,
            current_value=current_value,
            unit=unit,
            due_date=due_date,
        )

        key_result_add.additional_properties = d
        return key_result_add

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
