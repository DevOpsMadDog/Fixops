from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.board_column import BoardColumn
from ..models.card_priority import CardPriority
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.card_comment import CardComment


T = TypeVar("T", bound="RemediationCard")


@_attrs_define
class RemediationCard:
    """A single Kanban card tracking a security finding remediation.

    Attributes:
        finding_id (str):
        title (str):
        id (str | Unset):
        description (str | Unset):  Default: ''.
        assignee (None | str | Unset):
        column (BoardColumn | Unset): Kanban columns for security remediation workflow.
        priority (CardPriority | Unset): Priority levels for remediation cards.
        due_date (datetime.datetime | None | Unset):
        labels (list[str] | Unset):
        comments (list[CardComment] | Unset):
        created_at (datetime.datetime | Unset):
        moved_at (datetime.datetime | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    finding_id: str
    title: str
    id: str | Unset = UNSET
    description: str | Unset = ""
    assignee: None | str | Unset = UNSET
    column: BoardColumn | Unset = UNSET
    priority: CardPriority | Unset = UNSET
    due_date: datetime.datetime | None | Unset = UNSET
    labels: list[str] | Unset = UNSET
    comments: list[CardComment] | Unset = UNSET
    created_at: datetime.datetime | Unset = UNSET
    moved_at: datetime.datetime | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        title = self.title

        id = self.id

        description = self.description

        assignee: None | str | Unset
        if isinstance(self.assignee, Unset):
            assignee = UNSET
        else:
            assignee = self.assignee

        column: str | Unset = UNSET
        if not isinstance(self.column, Unset):
            column = self.column.value

        priority: str | Unset = UNSET
        if not isinstance(self.priority, Unset):
            priority = self.priority.value

        due_date: None | str | Unset
        if isinstance(self.due_date, Unset):
            due_date = UNSET
        elif isinstance(self.due_date, datetime.datetime):
            due_date = self.due_date.isoformat()
        else:
            due_date = self.due_date

        labels: list[str] | Unset = UNSET
        if not isinstance(self.labels, Unset):
            labels = self.labels

        comments: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.comments, Unset):
            comments = []
            for comments_item_data in self.comments:
                comments_item = comments_item_data.to_dict()
                comments.append(comments_item)

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        moved_at: str | Unset = UNSET
        if not isinstance(self.moved_at, Unset):
            moved_at = self.moved_at.isoformat()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "title": title,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if description is not UNSET:
            field_dict["description"] = description
        if assignee is not UNSET:
            field_dict["assignee"] = assignee
        if column is not UNSET:
            field_dict["column"] = column
        if priority is not UNSET:
            field_dict["priority"] = priority
        if due_date is not UNSET:
            field_dict["due_date"] = due_date
        if labels is not UNSET:
            field_dict["labels"] = labels
        if comments is not UNSET:
            field_dict["comments"] = comments
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if moved_at is not UNSET:
            field_dict["moved_at"] = moved_at
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.card_comment import CardComment

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        title = d.pop("title")

        id = d.pop("id", UNSET)

        description = d.pop("description", UNSET)

        def _parse_assignee(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignee = _parse_assignee(d.pop("assignee", UNSET))

        _column = d.pop("column", UNSET)
        column: BoardColumn | Unset
        if isinstance(_column, Unset):
            column = UNSET
        else:
            column = BoardColumn(_column)

        _priority = d.pop("priority", UNSET)
        priority: CardPriority | Unset
        if isinstance(_priority, Unset):
            priority = UNSET
        else:
            priority = CardPriority(_priority)

        def _parse_due_date(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                due_date_type_0 = isoparse(data)

                return due_date_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        due_date = _parse_due_date(d.pop("due_date", UNSET))

        labels = cast(list[str], d.pop("labels", UNSET))

        _comments = d.pop("comments", UNSET)
        comments: list[CardComment] | Unset = UNSET
        if _comments is not UNSET:
            comments = []
            for comments_item_data in _comments:
                comments_item = CardComment.from_dict(comments_item_data)

                comments.append(comments_item)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        _moved_at = d.pop("moved_at", UNSET)
        moved_at: datetime.datetime | Unset
        if isinstance(_moved_at, Unset):
            moved_at = UNSET
        else:
            moved_at = isoparse(_moved_at)

        org_id = d.pop("org_id", UNSET)

        remediation_card = cls(
            finding_id=finding_id,
            title=title,
            id=id,
            description=description,
            assignee=assignee,
            column=column,
            priority=priority,
            due_date=due_date,
            labels=labels,
            comments=comments,
            created_at=created_at,
            moved_at=moved_at,
            org_id=org_id,
        )

        remediation_card.additional_properties = d
        return remediation_card

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
