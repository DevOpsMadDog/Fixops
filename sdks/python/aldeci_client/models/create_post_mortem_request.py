from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_post_mortem_request_action_items_item import CreatePostMortemRequestActionItemsItem


T = TypeVar("T", bound="CreatePostMortemRequest")


@_attrs_define
class CreatePostMortemRequest:
    """
    Attributes:
        summary (str):
        root_cause (str):
        authored_by (str):
        impact (str | Unset):  Default: ''.
        timeline_summary (str | Unset):  Default: ''.
        lessons_learned (list[str] | Unset):
        action_items (list[CreatePostMortemRequestActionItemsItem] | Unset):
    """

    summary: str
    root_cause: str
    authored_by: str
    impact: str | Unset = ""
    timeline_summary: str | Unset = ""
    lessons_learned: list[str] | Unset = UNSET
    action_items: list[CreatePostMortemRequestActionItemsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        summary = self.summary

        root_cause = self.root_cause

        authored_by = self.authored_by

        impact = self.impact

        timeline_summary = self.timeline_summary

        lessons_learned: list[str] | Unset = UNSET
        if not isinstance(self.lessons_learned, Unset):
            lessons_learned = self.lessons_learned

        action_items: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.action_items, Unset):
            action_items = []
            for action_items_item_data in self.action_items:
                action_items_item = action_items_item_data.to_dict()
                action_items.append(action_items_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "summary": summary,
                "root_cause": root_cause,
                "authored_by": authored_by,
            }
        )
        if impact is not UNSET:
            field_dict["impact"] = impact
        if timeline_summary is not UNSET:
            field_dict["timeline_summary"] = timeline_summary
        if lessons_learned is not UNSET:
            field_dict["lessons_learned"] = lessons_learned
        if action_items is not UNSET:
            field_dict["action_items"] = action_items

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_post_mortem_request_action_items_item import CreatePostMortemRequestActionItemsItem

        d = dict(src_dict)
        summary = d.pop("summary")

        root_cause = d.pop("root_cause")

        authored_by = d.pop("authored_by")

        impact = d.pop("impact", UNSET)

        timeline_summary = d.pop("timeline_summary", UNSET)

        lessons_learned = cast(list[str], d.pop("lessons_learned", UNSET))

        _action_items = d.pop("action_items", UNSET)
        action_items: list[CreatePostMortemRequestActionItemsItem] | Unset = UNSET
        if _action_items is not UNSET:
            action_items = []
            for action_items_item_data in _action_items:
                action_items_item = CreatePostMortemRequestActionItemsItem.from_dict(action_items_item_data)

                action_items.append(action_items_item)

        create_post_mortem_request = cls(
            summary=summary,
            root_cause=root_cause,
            authored_by=authored_by,
            impact=impact,
            timeline_summary=timeline_summary,
            lessons_learned=lessons_learned,
            action_items=action_items,
        )

        create_post_mortem_request.additional_properties = d
        return create_post_mortem_request

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
