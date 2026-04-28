from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.update_dr_plan_request_communication_plan_type_0 import UpdateDRPlanRequestCommunicationPlanType0
    from ..models.update_dr_plan_request_runbook_steps_type_0_item import UpdateDRPlanRequestRunbookStepsType0Item


T = TypeVar("T", bound="UpdateDRPlanRequest")


@_attrs_define
class UpdateDRPlanRequest:
    """
    Attributes:
        name (None | str | Unset):
        priority_order (int | None | Unset):
        runbook_steps (list[UpdateDRPlanRequestRunbookStepsType0Item] | None | Unset):
        responsible_parties (list[str] | None | Unset):
        communication_plan (None | Unset | UpdateDRPlanRequestCommunicationPlanType0):
        rto_minutes (int | None | Unset):
        rpo_minutes (int | None | Unset):
        version (None | str | Unset):
        approved_by (None | str | Unset):
        next_review_at (None | str | Unset):
        tags (list[str] | None | Unset):
    """

    name: None | str | Unset = UNSET
    priority_order: int | None | Unset = UNSET
    runbook_steps: list[UpdateDRPlanRequestRunbookStepsType0Item] | None | Unset = UNSET
    responsible_parties: list[str] | None | Unset = UNSET
    communication_plan: None | Unset | UpdateDRPlanRequestCommunicationPlanType0 = UNSET
    rto_minutes: int | None | Unset = UNSET
    rpo_minutes: int | None | Unset = UNSET
    version: None | str | Unset = UNSET
    approved_by: None | str | Unset = UNSET
    next_review_at: None | str | Unset = UNSET
    tags: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.update_dr_plan_request_communication_plan_type_0 import UpdateDRPlanRequestCommunicationPlanType0

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        priority_order: int | None | Unset
        if isinstance(self.priority_order, Unset):
            priority_order = UNSET
        else:
            priority_order = self.priority_order

        runbook_steps: list[dict[str, Any]] | None | Unset
        if isinstance(self.runbook_steps, Unset):
            runbook_steps = UNSET
        elif isinstance(self.runbook_steps, list):
            runbook_steps = []
            for runbook_steps_type_0_item_data in self.runbook_steps:
                runbook_steps_type_0_item = runbook_steps_type_0_item_data.to_dict()
                runbook_steps.append(runbook_steps_type_0_item)

        else:
            runbook_steps = self.runbook_steps

        responsible_parties: list[str] | None | Unset
        if isinstance(self.responsible_parties, Unset):
            responsible_parties = UNSET
        elif isinstance(self.responsible_parties, list):
            responsible_parties = self.responsible_parties

        else:
            responsible_parties = self.responsible_parties

        communication_plan: dict[str, Any] | None | Unset
        if isinstance(self.communication_plan, Unset):
            communication_plan = UNSET
        elif isinstance(self.communication_plan, UpdateDRPlanRequestCommunicationPlanType0):
            communication_plan = self.communication_plan.to_dict()
        else:
            communication_plan = self.communication_plan

        rto_minutes: int | None | Unset
        if isinstance(self.rto_minutes, Unset):
            rto_minutes = UNSET
        else:
            rto_minutes = self.rto_minutes

        rpo_minutes: int | None | Unset
        if isinstance(self.rpo_minutes, Unset):
            rpo_minutes = UNSET
        else:
            rpo_minutes = self.rpo_minutes

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        approved_by: None | str | Unset
        if isinstance(self.approved_by, Unset):
            approved_by = UNSET
        else:
            approved_by = self.approved_by

        next_review_at: None | str | Unset
        if isinstance(self.next_review_at, Unset):
            next_review_at = UNSET
        else:
            next_review_at = self.next_review_at

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
        if priority_order is not UNSET:
            field_dict["priority_order"] = priority_order
        if runbook_steps is not UNSET:
            field_dict["runbook_steps"] = runbook_steps
        if responsible_parties is not UNSET:
            field_dict["responsible_parties"] = responsible_parties
        if communication_plan is not UNSET:
            field_dict["communication_plan"] = communication_plan
        if rto_minutes is not UNSET:
            field_dict["rto_minutes"] = rto_minutes
        if rpo_minutes is not UNSET:
            field_dict["rpo_minutes"] = rpo_minutes
        if version is not UNSET:
            field_dict["version"] = version
        if approved_by is not UNSET:
            field_dict["approved_by"] = approved_by
        if next_review_at is not UNSET:
            field_dict["next_review_at"] = next_review_at
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.update_dr_plan_request_communication_plan_type_0 import UpdateDRPlanRequestCommunicationPlanType0
        from ..models.update_dr_plan_request_runbook_steps_type_0_item import UpdateDRPlanRequestRunbookStepsType0Item

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_priority_order(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        priority_order = _parse_priority_order(d.pop("priority_order", UNSET))

        def _parse_runbook_steps(data: object) -> list[UpdateDRPlanRequestRunbookStepsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                runbook_steps_type_0 = []
                _runbook_steps_type_0 = data
                for runbook_steps_type_0_item_data in _runbook_steps_type_0:
                    runbook_steps_type_0_item = UpdateDRPlanRequestRunbookStepsType0Item.from_dict(
                        runbook_steps_type_0_item_data
                    )

                    runbook_steps_type_0.append(runbook_steps_type_0_item)

                return runbook_steps_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[UpdateDRPlanRequestRunbookStepsType0Item] | None | Unset, data)

        runbook_steps = _parse_runbook_steps(d.pop("runbook_steps", UNSET))

        def _parse_responsible_parties(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                responsible_parties_type_0 = cast(list[str], data)

                return responsible_parties_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        responsible_parties = _parse_responsible_parties(d.pop("responsible_parties", UNSET))

        def _parse_communication_plan(data: object) -> None | Unset | UpdateDRPlanRequestCommunicationPlanType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                communication_plan_type_0 = UpdateDRPlanRequestCommunicationPlanType0.from_dict(data)

                return communication_plan_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UpdateDRPlanRequestCommunicationPlanType0, data)

        communication_plan = _parse_communication_plan(d.pop("communication_plan", UNSET))

        def _parse_rto_minutes(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        rto_minutes = _parse_rto_minutes(d.pop("rto_minutes", UNSET))

        def _parse_rpo_minutes(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        rpo_minutes = _parse_rpo_minutes(d.pop("rpo_minutes", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        def _parse_approved_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        approved_by = _parse_approved_by(d.pop("approved_by", UNSET))

        def _parse_next_review_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        next_review_at = _parse_next_review_at(d.pop("next_review_at", UNSET))

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

        update_dr_plan_request = cls(
            name=name,
            priority_order=priority_order,
            runbook_steps=runbook_steps,
            responsible_parties=responsible_parties,
            communication_plan=communication_plan,
            rto_minutes=rto_minutes,
            rpo_minutes=rpo_minutes,
            version=version,
            approved_by=approved_by,
            next_review_at=next_review_at,
            tags=tags,
        )

        update_dr_plan_request.additional_properties = d
        return update_dr_plan_request

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
