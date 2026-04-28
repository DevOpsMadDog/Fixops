from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GitHubIssueItem")


@_attrs_define
class GitHubIssueItem:
    """
    Attributes:
        number (int):
        title (str):
        state (str):
        url (str):
        labels (list[str]):
        assignees (list[str]):
        created_at (str):
        updated_at (str):
        closed_at (None | str | Unset):
    """

    number: int
    title: str
    state: str
    url: str
    labels: list[str]
    assignees: list[str]
    created_at: str
    updated_at: str
    closed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        number = self.number

        title = self.title

        state = self.state

        url = self.url

        labels = self.labels

        assignees = self.assignees

        created_at = self.created_at

        updated_at = self.updated_at

        closed_at: None | str | Unset
        if isinstance(self.closed_at, Unset):
            closed_at = UNSET
        else:
            closed_at = self.closed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "number": number,
                "title": title,
                "state": state,
                "url": url,
                "labels": labels,
                "assignees": assignees,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )
        if closed_at is not UNSET:
            field_dict["closed_at"] = closed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        number = d.pop("number")

        title = d.pop("title")

        state = d.pop("state")

        url = d.pop("url")

        labels = cast(list[str], d.pop("labels"))

        assignees = cast(list[str], d.pop("assignees"))

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        def _parse_closed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        closed_at = _parse_closed_at(d.pop("closed_at", UNSET))

        git_hub_issue_item = cls(
            number=number,
            title=title,
            state=state,
            url=url,
            labels=labels,
            assignees=assignees,
            created_at=created_at,
            updated_at=updated_at,
            closed_at=closed_at,
        )

        git_hub_issue_item.additional_properties = d
        return git_hub_issue_item

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
