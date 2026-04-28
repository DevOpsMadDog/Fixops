from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.board_presentation_in_key_metrics import BoardPresentationInKeyMetrics


T = TypeVar("T", bound="BoardPresentationIn")


@_attrs_define
class BoardPresentationIn:
    """
    Attributes:
        title (str | Unset):  Default: ''.
        presentation_date (str | Unset):  Default: ''.
        audience (str | Unset):  Default: 'board'.
        risk_summary (str | Unset):  Default: ''.
        key_metrics (BoardPresentationInKeyMetrics | Unset):
        action_items (list[str] | Unset):
    """

    title: str | Unset = ""
    presentation_date: str | Unset = ""
    audience: str | Unset = "board"
    risk_summary: str | Unset = ""
    key_metrics: BoardPresentationInKeyMetrics | Unset = UNSET
    action_items: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        presentation_date = self.presentation_date

        audience = self.audience

        risk_summary = self.risk_summary

        key_metrics: dict[str, Any] | Unset = UNSET
        if not isinstance(self.key_metrics, Unset):
            key_metrics = self.key_metrics.to_dict()

        action_items: list[str] | Unset = UNSET
        if not isinstance(self.action_items, Unset):
            action_items = self.action_items

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if title is not UNSET:
            field_dict["title"] = title
        if presentation_date is not UNSET:
            field_dict["presentation_date"] = presentation_date
        if audience is not UNSET:
            field_dict["audience"] = audience
        if risk_summary is not UNSET:
            field_dict["risk_summary"] = risk_summary
        if key_metrics is not UNSET:
            field_dict["key_metrics"] = key_metrics
        if action_items is not UNSET:
            field_dict["action_items"] = action_items

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.board_presentation_in_key_metrics import BoardPresentationInKeyMetrics

        d = dict(src_dict)
        title = d.pop("title", UNSET)

        presentation_date = d.pop("presentation_date", UNSET)

        audience = d.pop("audience", UNSET)

        risk_summary = d.pop("risk_summary", UNSET)

        _key_metrics = d.pop("key_metrics", UNSET)
        key_metrics: BoardPresentationInKeyMetrics | Unset
        if isinstance(_key_metrics, Unset):
            key_metrics = UNSET
        else:
            key_metrics = BoardPresentationInKeyMetrics.from_dict(_key_metrics)

        action_items = cast(list[str], d.pop("action_items", UNSET))

        board_presentation_in = cls(
            title=title,
            presentation_date=presentation_date,
            audience=audience,
            risk_summary=risk_summary,
            key_metrics=key_metrics,
            action_items=action_items,
        )

        board_presentation_in.additional_properties = d
        return board_presentation_in

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
