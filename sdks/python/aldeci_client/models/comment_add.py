from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CommentAdd")


@_attrs_define
class CommentAdd:
    """
    Attributes:
        author_id (str):
        body (str):
        comment_type (str | Unset):  Default: 'comment'.
    """

    author_id: str
    body: str
    comment_type: str | Unset = "comment"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        author_id = self.author_id

        body = self.body

        comment_type = self.comment_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "author_id": author_id,
                "body": body,
            }
        )
        if comment_type is not UNSET:
            field_dict["comment_type"] = comment_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        author_id = d.pop("author_id")

        body = d.pop("body")

        comment_type = d.pop("comment_type", UNSET)

        comment_add = cls(
            author_id=author_id,
            body=body,
            comment_type=comment_type,
        )

        comment_add.additional_properties = d
        return comment_add

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
