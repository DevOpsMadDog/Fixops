from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateFreezePeriodRequest")


@_attrs_define
class CreateFreezePeriodRequest:
    """
    Attributes:
        name (str):
        start_time (datetime.datetime):
        end_time (datetime.datetime):
        reason (str):
        exception_allowed (bool | Unset):  Default: False.
    """

    name: str
    start_time: datetime.datetime
    end_time: datetime.datetime
    reason: str
    exception_allowed: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        start_time = self.start_time.isoformat()

        end_time = self.end_time.isoformat()

        reason = self.reason

        exception_allowed = self.exception_allowed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "start_time": start_time,
                "end_time": end_time,
                "reason": reason,
            }
        )
        if exception_allowed is not UNSET:
            field_dict["exception_allowed"] = exception_allowed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        start_time = isoparse(d.pop("start_time"))

        end_time = isoparse(d.pop("end_time"))

        reason = d.pop("reason")

        exception_allowed = d.pop("exception_allowed", UNSET)

        create_freeze_period_request = cls(
            name=name,
            start_time=start_time,
            end_time=end_time,
            reason=reason,
            exception_allowed=exception_allowed,
        )

        create_freeze_period_request.additional_properties = d
        return create_freeze_period_request

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
