from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.playbook_trigger import PlaybookTrigger
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.soar_playbook_actions_item import SOARPlaybookActionsItem
    from ..models.soar_playbook_conditions import SOARPlaybookConditions


T = TypeVar("T", bound="SOARPlaybook")


@_attrs_define
class SOARPlaybook:
    """A SOAR playbook definition with trigger, conditions, and actions.

    Attributes:
        name (str):
        trigger (PlaybookTrigger): Events that can trigger a SOAR playbook.
        id (str | Unset):
        conditions (SOARPlaybookConditions | Unset):
        actions (list[SOARPlaybookActionsItem] | Unset):
        enabled (bool | Unset):  Default: True.
        execution_count (int | Unset):  Default: 0.
        avg_response_seconds (float | Unset):  Default: 0.0.
        org_id (str | Unset):  Default: 'default'.
        created_at (datetime.datetime | Unset):
        updated_at (datetime.datetime | Unset):
    """

    name: str
    trigger: PlaybookTrigger
    id: str | Unset = UNSET
    conditions: SOARPlaybookConditions | Unset = UNSET
    actions: list[SOARPlaybookActionsItem] | Unset = UNSET
    enabled: bool | Unset = True
    execution_count: int | Unset = 0
    avg_response_seconds: float | Unset = 0.0
    org_id: str | Unset = "default"
    created_at: datetime.datetime | Unset = UNSET
    updated_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        trigger = self.trigger.value

        id = self.id

        conditions: dict[str, Any] | Unset = UNSET
        if not isinstance(self.conditions, Unset):
            conditions = self.conditions.to_dict()

        actions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.actions, Unset):
            actions = []
            for actions_item_data in self.actions:
                actions_item = actions_item_data.to_dict()
                actions.append(actions_item)

        enabled = self.enabled

        execution_count = self.execution_count

        avg_response_seconds = self.avg_response_seconds

        org_id = self.org_id

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        updated_at: str | Unset = UNSET
        if not isinstance(self.updated_at, Unset):
            updated_at = self.updated_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "trigger": trigger,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if conditions is not UNSET:
            field_dict["conditions"] = conditions
        if actions is not UNSET:
            field_dict["actions"] = actions
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if execution_count is not UNSET:
            field_dict["execution_count"] = execution_count
        if avg_response_seconds is not UNSET:
            field_dict["avg_response_seconds"] = avg_response_seconds
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.soar_playbook_actions_item import SOARPlaybookActionsItem
        from ..models.soar_playbook_conditions import SOARPlaybookConditions

        d = dict(src_dict)
        name = d.pop("name")

        trigger = PlaybookTrigger(d.pop("trigger"))

        id = d.pop("id", UNSET)

        _conditions = d.pop("conditions", UNSET)
        conditions: SOARPlaybookConditions | Unset
        if isinstance(_conditions, Unset):
            conditions = UNSET
        else:
            conditions = SOARPlaybookConditions.from_dict(_conditions)

        _actions = d.pop("actions", UNSET)
        actions: list[SOARPlaybookActionsItem] | Unset = UNSET
        if _actions is not UNSET:
            actions = []
            for actions_item_data in _actions:
                actions_item = SOARPlaybookActionsItem.from_dict(actions_item_data)

                actions.append(actions_item)

        enabled = d.pop("enabled", UNSET)

        execution_count = d.pop("execution_count", UNSET)

        avg_response_seconds = d.pop("avg_response_seconds", UNSET)

        org_id = d.pop("org_id", UNSET)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        _updated_at = d.pop("updated_at", UNSET)
        updated_at: datetime.datetime | Unset
        if isinstance(_updated_at, Unset):
            updated_at = UNSET
        else:
            updated_at = isoparse(_updated_at)

        soar_playbook = cls(
            name=name,
            trigger=trigger,
            id=id,
            conditions=conditions,
            actions=actions,
            enabled=enabled,
            execution_count=execution_count,
            avg_response_seconds=avg_response_seconds,
            org_id=org_id,
            created_at=created_at,
            updated_at=updated_at,
        )

        soar_playbook.additional_properties = d
        return soar_playbook

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
