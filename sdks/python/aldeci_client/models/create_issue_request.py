from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.finding_request import FindingRequest


T = TypeVar("T", bound="CreateIssueRequest")


@_attrs_define
class CreateIssueRequest:
    """Create a GitHub issue from a finding.

    Attributes:
        finding (FindingRequest): A finding to create or sync as a GitHub issue.
        assignee (None | str | Unset): GitHub username to assign
        extra_labels (list[str] | Unset): Additional labels
    """

    finding: FindingRequest
    assignee: None | str | Unset = UNSET
    extra_labels: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding = self.finding.to_dict()

        assignee: None | str | Unset
        if isinstance(self.assignee, Unset):
            assignee = UNSET
        else:
            assignee = self.assignee

        extra_labels: list[str] | Unset = UNSET
        if not isinstance(self.extra_labels, Unset):
            extra_labels = self.extra_labels

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding": finding,
            }
        )
        if assignee is not UNSET:
            field_dict["assignee"] = assignee
        if extra_labels is not UNSET:
            field_dict["extra_labels"] = extra_labels

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.finding_request import FindingRequest

        d = dict(src_dict)
        finding = FindingRequest.from_dict(d.pop("finding"))

        def _parse_assignee(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignee = _parse_assignee(d.pop("assignee", UNSET))

        extra_labels = cast(list[str], d.pop("extra_labels", UNSET))

        create_issue_request = cls(
            finding=finding,
            assignee=assignee,
            extra_labels=extra_labels,
        )

        create_issue_request.additional_properties = d
        return create_issue_request

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
