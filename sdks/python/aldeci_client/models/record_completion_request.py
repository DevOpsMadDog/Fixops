from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordCompletionRequest")


@_attrs_define
class RecordCompletionRequest:
    """
    Attributes:
        user_email (str): User's email address
        module_id (str): Training module ID
        score (int): Score achieved (0-100)
        org_id (str | Unset): Organisation ID Default: 'default'.
        completed_at (datetime.datetime | None | Unset): Completion timestamp (defaults to now)
    """

    user_email: str
    module_id: str
    score: int
    org_id: str | Unset = "default"
    completed_at: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_email = self.user_email

        module_id = self.module_id

        score = self.score

        org_id = self.org_id

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        elif isinstance(self.completed_at, datetime.datetime):
            completed_at = self.completed_at.isoformat()
        else:
            completed_at = self.completed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_email": user_email,
                "module_id": module_id,
                "score": score,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_email = d.pop("user_email")

        module_id = d.pop("module_id")

        score = d.pop("score")

        org_id = d.pop("org_id", UNSET)

        def _parse_completed_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                completed_at_type_0 = isoparse(data)

                return completed_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        record_completion_request = cls(
            user_email=user_email,
            module_id=module_id,
            score=score,
            org_id=org_id,
            completed_at=completed_at,
        )

        record_completion_request.additional_properties = d
        return record_completion_request

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
