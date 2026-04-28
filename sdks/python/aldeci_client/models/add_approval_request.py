from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.approval_decision import ApprovalDecision
from ..types import UNSET, Unset

T = TypeVar("T", bound="AddApprovalRequest")


@_attrs_define
class AddApprovalRequest:
    """
    Attributes:
        approver_id (str):
        approver_name (str):
        approver_role (str):
        decision (ApprovalDecision):
        comments (None | str | Unset):
        conditions (list[str] | Unset):
    """

    approver_id: str
    approver_name: str
    approver_role: str
    decision: ApprovalDecision
    comments: None | str | Unset = UNSET
    conditions: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        approver_id = self.approver_id

        approver_name = self.approver_name

        approver_role = self.approver_role

        decision = self.decision.value

        comments: None | str | Unset
        if isinstance(self.comments, Unset):
            comments = UNSET
        else:
            comments = self.comments

        conditions: list[str] | Unset = UNSET
        if not isinstance(self.conditions, Unset):
            conditions = self.conditions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "approver_id": approver_id,
                "approver_name": approver_name,
                "approver_role": approver_role,
                "decision": decision,
            }
        )
        if comments is not UNSET:
            field_dict["comments"] = comments
        if conditions is not UNSET:
            field_dict["conditions"] = conditions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        approver_id = d.pop("approver_id")

        approver_name = d.pop("approver_name")

        approver_role = d.pop("approver_role")

        decision = ApprovalDecision(d.pop("decision"))

        def _parse_comments(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        comments = _parse_comments(d.pop("comments", UNSET))

        conditions = cast(list[str], d.pop("conditions", UNSET))

        add_approval_request = cls(
            approver_id=approver_id,
            approver_name=approver_name,
            approver_role=approver_role,
            decision=decision,
            comments=comments,
            conditions=conditions,
        )

        add_approval_request.additional_properties = d
        return add_approval_request

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
