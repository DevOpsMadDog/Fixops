from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.hunt_status import HuntStatus
from ..models.hunt_trigger_type import HuntTriggerType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.hunt_workflow_trigger_context import HuntWorkflowTriggerContext


T = TypeVar("T", bound="HuntWorkflow")


@_attrs_define
class HuntWorkflow:
    """A structured threat hunt workflow.

    Attributes:
        hypothesis_id (str):
        hypothesis_name (str):
        org_id (str):
        id (str | Unset):
        status (HuntStatus | Unset):
        trigger_type (HuntTriggerType | Unset):
        trigger_context (HuntWorkflowTriggerContext | Unset):
        analyst (str | Unset):  Default: 'system'.
        started_at (datetime.datetime | None | Unset):
        completed_at (datetime.datetime | None | Unset):
        findings_count (int | Unset):  Default: 0.
        data_sources_queried (list[str] | Unset):
        notes (str | Unset):  Default: ''.
        created_at (datetime.datetime | Unset):
    """

    hypothesis_id: str
    hypothesis_name: str
    org_id: str
    id: str | Unset = UNSET
    status: HuntStatus | Unset = UNSET
    trigger_type: HuntTriggerType | Unset = UNSET
    trigger_context: HuntWorkflowTriggerContext | Unset = UNSET
    analyst: str | Unset = "system"
    started_at: datetime.datetime | None | Unset = UNSET
    completed_at: datetime.datetime | None | Unset = UNSET
    findings_count: int | Unset = 0
    data_sources_queried: list[str] | Unset = UNSET
    notes: str | Unset = ""
    created_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hypothesis_id = self.hypothesis_id

        hypothesis_name = self.hypothesis_name

        org_id = self.org_id

        id = self.id

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        trigger_type: str | Unset = UNSET
        if not isinstance(self.trigger_type, Unset):
            trigger_type = self.trigger_type.value

        trigger_context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.trigger_context, Unset):
            trigger_context = self.trigger_context.to_dict()

        analyst = self.analyst

        started_at: None | str | Unset
        if isinstance(self.started_at, Unset):
            started_at = UNSET
        elif isinstance(self.started_at, datetime.datetime):
            started_at = self.started_at.isoformat()
        else:
            started_at = self.started_at

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        elif isinstance(self.completed_at, datetime.datetime):
            completed_at = self.completed_at.isoformat()
        else:
            completed_at = self.completed_at

        findings_count = self.findings_count

        data_sources_queried: list[str] | Unset = UNSET
        if not isinstance(self.data_sources_queried, Unset):
            data_sources_queried = self.data_sources_queried

        notes = self.notes

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "hypothesis_id": hypothesis_id,
                "hypothesis_name": hypothesis_name,
                "org_id": org_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if status is not UNSET:
            field_dict["status"] = status
        if trigger_type is not UNSET:
            field_dict["trigger_type"] = trigger_type
        if trigger_context is not UNSET:
            field_dict["trigger_context"] = trigger_context
        if analyst is not UNSET:
            field_dict["analyst"] = analyst
        if started_at is not UNSET:
            field_dict["started_at"] = started_at
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if data_sources_queried is not UNSET:
            field_dict["data_sources_queried"] = data_sources_queried
        if notes is not UNSET:
            field_dict["notes"] = notes
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.hunt_workflow_trigger_context import HuntWorkflowTriggerContext

        d = dict(src_dict)
        hypothesis_id = d.pop("hypothesis_id")

        hypothesis_name = d.pop("hypothesis_name")

        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        _status = d.pop("status", UNSET)
        status: HuntStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = HuntStatus(_status)

        _trigger_type = d.pop("trigger_type", UNSET)
        trigger_type: HuntTriggerType | Unset
        if isinstance(_trigger_type, Unset):
            trigger_type = UNSET
        else:
            trigger_type = HuntTriggerType(_trigger_type)

        _trigger_context = d.pop("trigger_context", UNSET)
        trigger_context: HuntWorkflowTriggerContext | Unset
        if isinstance(_trigger_context, Unset):
            trigger_context = UNSET
        else:
            trigger_context = HuntWorkflowTriggerContext.from_dict(_trigger_context)

        analyst = d.pop("analyst", UNSET)

        def _parse_started_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                started_at_type_0 = isoparse(data)

                return started_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        started_at = _parse_started_at(d.pop("started_at", UNSET))

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

        findings_count = d.pop("findings_count", UNSET)

        data_sources_queried = cast(list[str], d.pop("data_sources_queried", UNSET))

        notes = d.pop("notes", UNSET)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        hunt_workflow = cls(
            hypothesis_id=hypothesis_id,
            hypothesis_name=hypothesis_name,
            org_id=org_id,
            id=id,
            status=status,
            trigger_type=trigger_type,
            trigger_context=trigger_context,
            analyst=analyst,
            started_at=started_at,
            completed_at=completed_at,
            findings_count=findings_count,
            data_sources_queried=data_sources_queried,
            notes=notes,
            created_at=created_at,
        )

        hunt_workflow.additional_properties = d
        return hunt_workflow

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
