from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.playbook_update_request_steps_type_0_item import PlaybookUpdateRequestStepsType0Item
    from ..models.playbook_update_request_trigger_conditions_type_0 import PlaybookUpdateRequestTriggerConditionsType0


T = TypeVar("T", bound="PlaybookUpdateRequest")


@_attrs_define
class PlaybookUpdateRequest:
    """Request model for updating a playbook.

    Attributes:
        name (None | str | Unset):
        description (None | str | Unset):
        trigger_conditions (None | PlaybookUpdateRequestTriggerConditionsType0 | Unset):
        steps (list[PlaybookUpdateRequestStepsType0Item] | None | Unset):
        status (None | str | Unset):
        tags (list[str] | None | Unset):
    """

    name: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    trigger_conditions: None | PlaybookUpdateRequestTriggerConditionsType0 | Unset = UNSET
    steps: list[PlaybookUpdateRequestStepsType0Item] | None | Unset = UNSET
    status: None | str | Unset = UNSET
    tags: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.playbook_update_request_trigger_conditions_type_0 import (
            PlaybookUpdateRequestTriggerConditionsType0,
        )

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

        trigger_conditions: dict[str, Any] | None | Unset
        if isinstance(self.trigger_conditions, Unset):
            trigger_conditions = UNSET
        elif isinstance(self.trigger_conditions, PlaybookUpdateRequestTriggerConditionsType0):
            trigger_conditions = self.trigger_conditions.to_dict()
        else:
            trigger_conditions = self.trigger_conditions

        steps: list[dict[str, Any]] | None | Unset
        if isinstance(self.steps, Unset):
            steps = UNSET
        elif isinstance(self.steps, list):
            steps = []
            for steps_type_0_item_data in self.steps:
                steps_type_0_item = steps_type_0_item_data.to_dict()
                steps.append(steps_type_0_item)

        else:
            steps = self.steps

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        tags: list[str] | None | Unset
        if isinstance(self.tags, Unset):
            tags = UNSET
        elif isinstance(self.tags, list):
            tags = self.tags

        else:
            tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if description is not UNSET:
            field_dict["description"] = description
        if trigger_conditions is not UNSET:
            field_dict["trigger_conditions"] = trigger_conditions
        if steps is not UNSET:
            field_dict["steps"] = steps
        if status is not UNSET:
            field_dict["status"] = status
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.playbook_update_request_steps_type_0_item import PlaybookUpdateRequestStepsType0Item
        from ..models.playbook_update_request_trigger_conditions_type_0 import (
            PlaybookUpdateRequestTriggerConditionsType0,
        )

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

        def _parse_trigger_conditions(data: object) -> None | PlaybookUpdateRequestTriggerConditionsType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                trigger_conditions_type_0 = PlaybookUpdateRequestTriggerConditionsType0.from_dict(data)

                return trigger_conditions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PlaybookUpdateRequestTriggerConditionsType0 | Unset, data)

        trigger_conditions = _parse_trigger_conditions(d.pop("trigger_conditions", UNSET))

        def _parse_steps(data: object) -> list[PlaybookUpdateRequestStepsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                steps_type_0 = []
                _steps_type_0 = data
                for steps_type_0_item_data in _steps_type_0:
                    steps_type_0_item = PlaybookUpdateRequestStepsType0Item.from_dict(steps_type_0_item_data)

                    steps_type_0.append(steps_type_0_item)

                return steps_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[PlaybookUpdateRequestStepsType0Item] | None | Unset, data)

        steps = _parse_steps(d.pop("steps", UNSET))

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_tags(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                tags_type_0 = cast(list[str], data)

                return tags_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        tags = _parse_tags(d.pop("tags", UNSET))

        playbook_update_request = cls(
            name=name,
            description=description,
            trigger_conditions=trigger_conditions,
            steps=steps,
            status=status,
            tags=tags,
        )

        playbook_update_request.additional_properties = d
        return playbook_update_request

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
