from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

T = TypeVar("T", bound="CommentResponse")


@_attrs_define
class CommentResponse:
    """Response from adding a comment.

    Attributes:
        comment_id (str):
        finding_id (str):
        created_at (datetime.datetime):
        created_by (str):
        text (str):
    """

    comment_id: str
    finding_id: str
    created_at: datetime.datetime
    created_by: str
    text: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        comment_id = self.comment_id

        finding_id = self.finding_id

        created_at = self.created_at.isoformat()

        created_by = self.created_by

        text = self.text

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "comment_id": comment_id,
                "finding_id": finding_id,
                "created_at": created_at,
                "created_by": created_by,
                "text": text,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        comment_id = d.pop("comment_id")

        finding_id = d.pop("finding_id")

        created_at = isoparse(d.pop("created_at"))

        created_by = d.pop("created_by")

        text = d.pop("text")

        comment_response = cls(
            comment_id=comment_id,
            finding_id=finding_id,
            created_at=created_at,
            created_by=created_by,
            text=text,
        )

        comment_response.additional_properties = d
        return comment_response

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
