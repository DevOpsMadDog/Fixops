from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssignRequest")


@_attrs_define
class AssignRequest:
    """
    Attributes:
        assigned_to (str):
        target_date (datetime.datetime | None | Unset):
    """

    assigned_to: str
    target_date: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        assigned_to = self.assigned_to

        target_date: None | str | Unset
        if isinstance(self.target_date, Unset):
            target_date = UNSET
        elif isinstance(self.target_date, datetime.datetime):
            target_date = self.target_date.isoformat()
        else:
            target_date = self.target_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "assigned_to": assigned_to,
            }
        )
        if target_date is not UNSET:
            field_dict["target_date"] = target_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        assigned_to = d.pop("assigned_to")

        def _parse_target_date(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                target_date_type_0 = isoparse(data)

                return target_date_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        target_date = _parse_target_date(d.pop("target_date", UNSET))

        assign_request = cls(
            assigned_to=assigned_to,
            target_date=target_date,
        )

        assign_request.additional_properties = d
        return assign_request

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
