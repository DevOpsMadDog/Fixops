from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.playbook_create_request_steps_item import PlaybookCreateRequestStepsItem
    from ..models.playbook_create_request_trigger_conditions import PlaybookCreateRequestTriggerConditions


T = TypeVar("T", bound="PlaybookCreateRequest")


@_attrs_define
class PlaybookCreateRequest:
    """
    Attributes:
        name (str): Human-readable playbook name
        trigger_type (str | Unset): manual | auto_alert | scheduled Default: 'manual'.
        trigger_conditions (PlaybookCreateRequestTriggerConditions | Unset):
        steps (list[PlaybookCreateRequestStepsItem] | Unset):
        severity_filter (str | Unset): Minimum severity to trigger Default: 'medium'.
        enabled (bool | Unset):  Default: True.
        org_id (str | Unset): Organization identifier Default: 'default'.
    """

    name: str
    trigger_type: str | Unset = "manual"
    trigger_conditions: PlaybookCreateRequestTriggerConditions | Unset = UNSET
    steps: list[PlaybookCreateRequestStepsItem] | Unset = UNSET
    severity_filter: str | Unset = "medium"
    enabled: bool | Unset = True
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        trigger_type = self.trigger_type

        trigger_conditions: dict[str, Any] | Unset = UNSET
        if not isinstance(self.trigger_conditions, Unset):
            trigger_conditions = self.trigger_conditions.to_dict()

        steps: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.steps, Unset):
            steps = []
            for steps_item_data in self.steps:
                steps_item = steps_item_data.to_dict()
                steps.append(steps_item)

        severity_filter = self.severity_filter

        enabled = self.enabled

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if trigger_type is not UNSET:
            field_dict["trigger_type"] = trigger_type
        if trigger_conditions is not UNSET:
            field_dict["trigger_conditions"] = trigger_conditions
        if steps is not UNSET:
            field_dict["steps"] = steps
        if severity_filter is not UNSET:
            field_dict["severity_filter"] = severity_filter
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.playbook_create_request_steps_item import PlaybookCreateRequestStepsItem
        from ..models.playbook_create_request_trigger_conditions import PlaybookCreateRequestTriggerConditions

        d = dict(src_dict)
        name = d.pop("name")

        trigger_type = d.pop("trigger_type", UNSET)

        _trigger_conditions = d.pop("trigger_conditions", UNSET)
        trigger_conditions: PlaybookCreateRequestTriggerConditions | Unset
        if isinstance(_trigger_conditions, Unset):
            trigger_conditions = UNSET
        else:
            trigger_conditions = PlaybookCreateRequestTriggerConditions.from_dict(_trigger_conditions)

        _steps = d.pop("steps", UNSET)
        steps: list[PlaybookCreateRequestStepsItem] | Unset = UNSET
        if _steps is not UNSET:
            steps = []
            for steps_item_data in _steps:
                steps_item = PlaybookCreateRequestStepsItem.from_dict(steps_item_data)

                steps.append(steps_item)

        severity_filter = d.pop("severity_filter", UNSET)

        enabled = d.pop("enabled", UNSET)

        org_id = d.pop("org_id", UNSET)

        playbook_create_request = cls(
            name=name,
            trigger_type=trigger_type,
            trigger_conditions=trigger_conditions,
            steps=steps,
            severity_filter=severity_filter,
            enabled=enabled,
            org_id=org_id,
        )

        playbook_create_request.additional_properties = d
        return playbook_create_request

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
