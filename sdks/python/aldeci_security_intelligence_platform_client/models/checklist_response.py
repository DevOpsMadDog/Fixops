from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.checklist_response_items_item import ChecklistResponseItemsItem


T = TypeVar("T", bound="ChecklistResponse")


@_attrs_define
class ChecklistResponse:
    """
    Attributes:
        org_id (str):
        onboarding_started (bool):
        items (list[ChecklistResponseItemsItem]):
        current_step (None | str | Unset):
        completion_percentage (float | None | Unset):
    """

    org_id: str
    onboarding_started: bool
    items: list[ChecklistResponseItemsItem]
    current_step: None | str | Unset = UNSET
    completion_percentage: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        onboarding_started = self.onboarding_started

        items = []
        for items_item_data in self.items:
            items_item = items_item_data.to_dict()
            items.append(items_item)

        current_step: None | str | Unset
        if isinstance(self.current_step, Unset):
            current_step = UNSET
        else:
            current_step = self.current_step

        completion_percentage: float | None | Unset
        if isinstance(self.completion_percentage, Unset):
            completion_percentage = UNSET
        else:
            completion_percentage = self.completion_percentage

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "onboarding_started": onboarding_started,
                "items": items,
            }
        )
        if current_step is not UNSET:
            field_dict["current_step"] = current_step
        if completion_percentage is not UNSET:
            field_dict["completion_percentage"] = completion_percentage

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.checklist_response_items_item import ChecklistResponseItemsItem

        d = dict(src_dict)
        org_id = d.pop("org_id")

        onboarding_started = d.pop("onboarding_started")

        items = []
        _items = d.pop("items")
        for items_item_data in _items:
            items_item = ChecklistResponseItemsItem.from_dict(items_item_data)

            items.append(items_item)

        def _parse_current_step(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        current_step = _parse_current_step(d.pop("current_step", UNSET))

        def _parse_completion_percentage(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        completion_percentage = _parse_completion_percentage(d.pop("completion_percentage", UNSET))

        checklist_response = cls(
            org_id=org_id,
            onboarding_started=onboarding_started,
            items=items,
            current_step=current_step,
            completion_percentage=completion_percentage,
        )

        checklist_response.additional_properties = d
        return checklist_response

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
