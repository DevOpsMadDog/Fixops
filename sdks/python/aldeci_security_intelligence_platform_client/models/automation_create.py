from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.automation_create_condition import AutomationCreateCondition


T = TypeVar("T", bound="AutomationCreate")


@_attrs_define
class AutomationCreate:
    """
    Attributes:
        automation_name (str):
        trigger_type (str | Unset):  Default: 'manual'.
        action_type (str | Unset):  Default: 'alert'.
        condition (AutomationCreateCondition | Unset):
        enabled (bool | Unset):  Default: True.
    """

    automation_name: str
    trigger_type: str | Unset = "manual"
    action_type: str | Unset = "alert"
    condition: AutomationCreateCondition | Unset = UNSET
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        automation_name = self.automation_name

        trigger_type = self.trigger_type

        action_type = self.action_type

        condition: dict[str, Any] | Unset = UNSET
        if not isinstance(self.condition, Unset):
            condition = self.condition.to_dict()

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "automation_name": automation_name,
            }
        )
        if trigger_type is not UNSET:
            field_dict["trigger_type"] = trigger_type
        if action_type is not UNSET:
            field_dict["action_type"] = action_type
        if condition is not UNSET:
            field_dict["condition"] = condition
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.automation_create_condition import AutomationCreateCondition

        d = dict(src_dict)
        automation_name = d.pop("automation_name")

        trigger_type = d.pop("trigger_type", UNSET)

        action_type = d.pop("action_type", UNSET)

        _condition = d.pop("condition", UNSET)
        condition: AutomationCreateCondition | Unset
        if isinstance(_condition, Unset):
            condition = UNSET
        else:
            condition = AutomationCreateCondition.from_dict(_condition)

        enabled = d.pop("enabled", UNSET)

        automation_create = cls(
            automation_name=automation_name,
            trigger_type=trigger_type,
            action_type=action_type,
            condition=condition,
            enabled=enabled,
        )

        automation_create.additional_properties = d
        return automation_create

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
