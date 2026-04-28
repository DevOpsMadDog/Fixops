from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.rule_response_config import RuleResponseConfig
    from ..models.rule_response_trigger_condition import RuleResponseTriggerCondition


T = TypeVar("T", bound="RuleResponse")


@_attrs_define
class RuleResponse:
    """
    Attributes:
        id (str):
        name (str):
        trigger_condition (RuleResponseTriggerCondition):
        action (str):
        config (RuleResponseConfig):
        enabled (bool):
        execution_count (int):
        last_triggered (None | str):
        org_id (str):
    """

    id: str
    name: str
    trigger_condition: RuleResponseTriggerCondition
    action: str
    config: RuleResponseConfig
    enabled: bool
    execution_count: int
    last_triggered: None | str
    org_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        trigger_condition = self.trigger_condition.to_dict()

        action = self.action

        config = self.config.to_dict()

        enabled = self.enabled

        execution_count = self.execution_count

        last_triggered: None | str
        last_triggered = self.last_triggered

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "trigger_condition": trigger_condition,
                "action": action,
                "config": config,
                "enabled": enabled,
                "execution_count": execution_count,
                "last_triggered": last_triggered,
                "org_id": org_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.rule_response_config import RuleResponseConfig
        from ..models.rule_response_trigger_condition import RuleResponseTriggerCondition

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        trigger_condition = RuleResponseTriggerCondition.from_dict(d.pop("trigger_condition"))

        action = d.pop("action")

        config = RuleResponseConfig.from_dict(d.pop("config"))

        enabled = d.pop("enabled")

        execution_count = d.pop("execution_count")

        def _parse_last_triggered(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        last_triggered = _parse_last_triggered(d.pop("last_triggered"))

        org_id = d.pop("org_id")

        rule_response = cls(
            id=id,
            name=name,
            trigger_condition=trigger_condition,
            action=action,
            config=config,
            enabled=enabled,
            execution_count=execution_count,
            last_triggered=last_triggered,
            org_id=org_id,
        )

        rule_response.additional_properties = d
        return rule_response

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
