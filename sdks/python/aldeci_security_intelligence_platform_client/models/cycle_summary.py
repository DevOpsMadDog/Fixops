from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.cycle_summary_actions_item import CycleSummaryActionsItem


T = TypeVar("T", bound="CycleSummary")


@_attrs_define
class CycleSummary:
    """
    Attributes:
        breaches_found (int):
        escalations_triggered (int):
        actions (list[CycleSummaryActionsItem]):
    """

    breaches_found: int
    escalations_triggered: int
    actions: list[CycleSummaryActionsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        breaches_found = self.breaches_found

        escalations_triggered = self.escalations_triggered

        actions = []
        for actions_item_data in self.actions:
            actions_item = actions_item_data.to_dict()
            actions.append(actions_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "breaches_found": breaches_found,
                "escalations_triggered": escalations_triggered,
                "actions": actions,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cycle_summary_actions_item import CycleSummaryActionsItem

        d = dict(src_dict)
        breaches_found = d.pop("breaches_found")

        escalations_triggered = d.pop("escalations_triggered")

        actions = []
        _actions = d.pop("actions")
        for actions_item_data in _actions:
            actions_item = CycleSummaryActionsItem.from_dict(actions_item_data)

            actions.append(actions_item)

        cycle_summary = cls(
            breaches_found=breaches_found,
            escalations_triggered=escalations_triggered,
            actions=actions,
        )

        cycle_summary.additional_properties = d
        return cycle_summary

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
