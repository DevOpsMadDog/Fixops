from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateIssueRequest")


@_attrs_define
class UpdateIssueRequest:
    """Add a comment to a GitHub issue.

    Attributes:
        finding_id (str): Finding identifier (used to look up issue number)
        comment (str): Markdown comment body
        issue_number (int | None | Unset): Override issue number if not linked
    """

    finding_id: str
    comment: str
    issue_number: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        comment = self.comment

        issue_number: int | None | Unset
        if isinstance(self.issue_number, Unset):
            issue_number = UNSET
        else:
            issue_number = self.issue_number

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "comment": comment,
            }
        )
        if issue_number is not UNSET:
            field_dict["issue_number"] = issue_number

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        comment = d.pop("comment")

        def _parse_issue_number(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        issue_number = _parse_issue_number(d.pop("issue_number", UNSET))

        update_issue_request = cls(
            finding_id=finding_id,
            comment=comment,
            issue_number=issue_number,
        )

        update_issue_request.additional_properties = d
        return update_issue_request

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
