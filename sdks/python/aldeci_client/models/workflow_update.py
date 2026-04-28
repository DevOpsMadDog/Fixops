from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.workflow_update_actions_type_0_item import WorkflowUpdateActionsType0Item
    from ..models.workflow_update_conditions_type_0_item import WorkflowUpdateConditionsType0Item


T = TypeVar("T", bound="WorkflowUpdate")


@_attrs_define
class WorkflowUpdate:
    """
    Attributes:
        name (None | str | Unset):
        description (None | str | Unset):
        trigger (None | str | Unset):
        conditions (list[WorkflowUpdateConditionsType0Item] | None | Unset):
        actions (list[WorkflowUpdateActionsType0Item] | None | Unset):
        enabled (bool | None | Unset):
    """

    name: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    trigger: None | str | Unset = UNSET
    conditions: list[WorkflowUpdateConditionsType0Item] | None | Unset = UNSET
    actions: list[WorkflowUpdateActionsType0Item] | None | Unset = UNSET
    enabled: bool | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        trigger: None | str | Unset
        if isinstance(self.trigger, Unset):
            trigger = UNSET
        else:
            trigger = self.trigger

        conditions: list[dict[str, Any]] | None | Unset
        if isinstance(self.conditions, Unset):
            conditions = UNSET
        elif isinstance(self.conditions, list):
            conditions = []
            for conditions_type_0_item_data in self.conditions:
                conditions_type_0_item = conditions_type_0_item_data.to_dict()
                conditions.append(conditions_type_0_item)

        else:
            conditions = self.conditions

        actions: list[dict[str, Any]] | None | Unset
        if isinstance(self.actions, Unset):
            actions = UNSET
        elif isinstance(self.actions, list):
            actions = []
            for actions_type_0_item_data in self.actions:
                actions_type_0_item = actions_type_0_item_data.to_dict()
                actions.append(actions_type_0_item)

        else:
            actions = self.actions

        enabled: bool | None | Unset
        if isinstance(self.enabled, Unset):
            enabled = UNSET
        else:
            enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if description is not UNSET:
            field_dict["description"] = description
        if trigger is not UNSET:
            field_dict["trigger"] = trigger
        if conditions is not UNSET:
            field_dict["conditions"] = conditions
        if actions is not UNSET:
            field_dict["actions"] = actions
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.workflow_update_actions_type_0_item import WorkflowUpdateActionsType0Item
        from ..models.workflow_update_conditions_type_0_item import WorkflowUpdateConditionsType0Item

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_trigger(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        trigger = _parse_trigger(d.pop("trigger", UNSET))

        def _parse_conditions(data: object) -> list[WorkflowUpdateConditionsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                conditions_type_0 = []
                _conditions_type_0 = data
                for conditions_type_0_item_data in _conditions_type_0:
                    conditions_type_0_item = WorkflowUpdateConditionsType0Item.from_dict(conditions_type_0_item_data)

                    conditions_type_0.append(conditions_type_0_item)

                return conditions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[WorkflowUpdateConditionsType0Item] | None | Unset, data)

        conditions = _parse_conditions(d.pop("conditions", UNSET))

        def _parse_actions(data: object) -> list[WorkflowUpdateActionsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                actions_type_0 = []
                _actions_type_0 = data
                for actions_type_0_item_data in _actions_type_0:
                    actions_type_0_item = WorkflowUpdateActionsType0Item.from_dict(actions_type_0_item_data)

                    actions_type_0.append(actions_type_0_item)

                return actions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[WorkflowUpdateActionsType0Item] | None | Unset, data)

        actions = _parse_actions(d.pop("actions", UNSET))

        def _parse_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        enabled = _parse_enabled(d.pop("enabled", UNSET))

        workflow_update = cls(
            name=name,
            description=description,
            trigger=trigger,
            conditions=conditions,
            actions=actions,
            enabled=enabled,
        )

        workflow_update.additional_properties = d
        return workflow_update

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
