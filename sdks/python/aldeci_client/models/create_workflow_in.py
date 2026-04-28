from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_workflow_in_trigger_condition import CreateWorkflowInTriggerCondition


T = TypeVar("T", bound="CreateWorkflowIn")


@_attrs_define
class CreateWorkflowIn:
    """
    Attributes:
        name (str): Workflow name
        trigger_type (str | Unset): vulnerability|alert|anomaly|policy_violation|incident|manual Default: 'manual'.
        trigger_condition (CreateWorkflowInTriggerCondition | Unset): JSON-serialized trigger rule
        action_type (str | Unset): patch|isolate|block|notify|script|api_call|rollback|quarantine Default: 'notify'.
        target_type (str | Unset): host|container|network|identity|application|cloud_resource Default: 'host'.
        automation_level (str | Unset): full|semi|manual Default: 'manual'.
    """

    name: str
    trigger_type: str | Unset = "manual"
    trigger_condition: CreateWorkflowInTriggerCondition | Unset = UNSET
    action_type: str | Unset = "notify"
    target_type: str | Unset = "host"
    automation_level: str | Unset = "manual"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        trigger_type = self.trigger_type

        trigger_condition: dict[str, Any] | Unset = UNSET
        if not isinstance(self.trigger_condition, Unset):
            trigger_condition = self.trigger_condition.to_dict()

        action_type = self.action_type

        target_type = self.target_type

        automation_level = self.automation_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if trigger_type is not UNSET:
            field_dict["trigger_type"] = trigger_type
        if trigger_condition is not UNSET:
            field_dict["trigger_condition"] = trigger_condition
        if action_type is not UNSET:
            field_dict["action_type"] = action_type
        if target_type is not UNSET:
            field_dict["target_type"] = target_type
        if automation_level is not UNSET:
            field_dict["automation_level"] = automation_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_workflow_in_trigger_condition import CreateWorkflowInTriggerCondition

        d = dict(src_dict)
        name = d.pop("name")

        trigger_type = d.pop("trigger_type", UNSET)

        _trigger_condition = d.pop("trigger_condition", UNSET)
        trigger_condition: CreateWorkflowInTriggerCondition | Unset
        if isinstance(_trigger_condition, Unset):
            trigger_condition = UNSET
        else:
            trigger_condition = CreateWorkflowInTriggerCondition.from_dict(_trigger_condition)

        action_type = d.pop("action_type", UNSET)

        target_type = d.pop("target_type", UNSET)

        automation_level = d.pop("automation_level", UNSET)

        create_workflow_in = cls(
            name=name,
            trigger_type=trigger_type,
            trigger_condition=trigger_condition,
            action_type=action_type,
            target_type=target_type,
            automation_level=automation_level,
        )

        create_workflow_in.additional_properties = d
        return create_workflow_in

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
