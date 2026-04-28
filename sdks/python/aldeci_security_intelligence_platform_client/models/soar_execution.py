from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.execution_status import ExecutionStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.soar_execution_actions_taken_item import SOARExecutionActionsTakenItem
    from ..models.soar_execution_trigger_event import SOARExecutionTriggerEvent


T = TypeVar("T", bound="SOARExecution")


@_attrs_define
class SOARExecution:
    """A record of a SOAR playbook execution.

    Attributes:
        playbook_id (str):
        id (str | Unset):
        trigger_event (SOARExecutionTriggerEvent | Unset):
        actions_taken (list[SOARExecutionActionsTakenItem] | Unset):
        started_at (datetime.datetime | Unset):
        completed_at (datetime.datetime | None | Unset):
        status (ExecutionStatus | Unset): Status of a SOAR playbook execution.
        org_id (str | Unset):  Default: 'default'.
        error_message (None | str | Unset):
    """

    playbook_id: str
    id: str | Unset = UNSET
    trigger_event: SOARExecutionTriggerEvent | Unset = UNSET
    actions_taken: list[SOARExecutionActionsTakenItem] | Unset = UNSET
    started_at: datetime.datetime | Unset = UNSET
    completed_at: datetime.datetime | None | Unset = UNSET
    status: ExecutionStatus | Unset = UNSET
    org_id: str | Unset = "default"
    error_message: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        playbook_id = self.playbook_id

        id = self.id

        trigger_event: dict[str, Any] | Unset = UNSET
        if not isinstance(self.trigger_event, Unset):
            trigger_event = self.trigger_event.to_dict()

        actions_taken: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.actions_taken, Unset):
            actions_taken = []
            for actions_taken_item_data in self.actions_taken:
                actions_taken_item = actions_taken_item_data.to_dict()
                actions_taken.append(actions_taken_item)

        started_at: str | Unset = UNSET
        if not isinstance(self.started_at, Unset):
            started_at = self.started_at.isoformat()

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        elif isinstance(self.completed_at, datetime.datetime):
            completed_at = self.completed_at.isoformat()
        else:
            completed_at = self.completed_at

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        org_id = self.org_id

        error_message: None | str | Unset
        if isinstance(self.error_message, Unset):
            error_message = UNSET
        else:
            error_message = self.error_message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "playbook_id": playbook_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if trigger_event is not UNSET:
            field_dict["trigger_event"] = trigger_event
        if actions_taken is not UNSET:
            field_dict["actions_taken"] = actions_taken
        if started_at is not UNSET:
            field_dict["started_at"] = started_at
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if status is not UNSET:
            field_dict["status"] = status
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if error_message is not UNSET:
            field_dict["error_message"] = error_message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.soar_execution_actions_taken_item import SOARExecutionActionsTakenItem
        from ..models.soar_execution_trigger_event import SOARExecutionTriggerEvent

        d = dict(src_dict)
        playbook_id = d.pop("playbook_id")

        id = d.pop("id", UNSET)

        _trigger_event = d.pop("trigger_event", UNSET)
        trigger_event: SOARExecutionTriggerEvent | Unset
        if isinstance(_trigger_event, Unset):
            trigger_event = UNSET
        else:
            trigger_event = SOARExecutionTriggerEvent.from_dict(_trigger_event)

        _actions_taken = d.pop("actions_taken", UNSET)
        actions_taken: list[SOARExecutionActionsTakenItem] | Unset = UNSET
        if _actions_taken is not UNSET:
            actions_taken = []
            for actions_taken_item_data in _actions_taken:
                actions_taken_item = SOARExecutionActionsTakenItem.from_dict(actions_taken_item_data)

                actions_taken.append(actions_taken_item)

        _started_at = d.pop("started_at", UNSET)
        started_at: datetime.datetime | Unset
        if isinstance(_started_at, Unset):
            started_at = UNSET
        else:
            started_at = isoparse(_started_at)

        def _parse_completed_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                completed_at_type_0 = isoparse(data)

                return completed_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        _status = d.pop("status", UNSET)
        status: ExecutionStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = ExecutionStatus(_status)

        org_id = d.pop("org_id", UNSET)

        def _parse_error_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error_message = _parse_error_message(d.pop("error_message", UNSET))

        soar_execution = cls(
            playbook_id=playbook_id,
            id=id,
            trigger_event=trigger_event,
            actions_taken=actions_taken,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            org_id=org_id,
            error_message=error_message,
        )

        soar_execution.additional_properties = d
        return soar_execution

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
