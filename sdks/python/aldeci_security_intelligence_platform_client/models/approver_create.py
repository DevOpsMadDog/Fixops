from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ApproverCreate")


@_attrs_define
class ApproverCreate:
    """
    Attributes:
        approver (str):
        decision (str | Unset):  Default: 'pending'.
        comments (str | Unset):  Default: ''.
    """

    approver: str
    decision: str | Unset = "pending"
    comments: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        approver = self.approver

        decision = self.decision

        comments = self.comments

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "approver": approver,
            }
        )
        if decision is not UNSET:
            field_dict["decision"] = decision
        if comments is not UNSET:
            field_dict["comments"] = comments

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        approver = d.pop("approver")

        decision = d.pop("decision", UNSET)

        comments = d.pop("comments", UNSET)

        approver_create = cls(
            approver=approver,
            decision=decision,
            comments=comments,
        )

        approver_create.additional_properties = d
        return approver_create

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
