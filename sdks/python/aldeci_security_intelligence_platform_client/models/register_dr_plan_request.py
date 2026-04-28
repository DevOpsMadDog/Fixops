from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.register_dr_plan_request_communication_plan import RegisterDRPlanRequestCommunicationPlan
    from ..models.register_dr_plan_request_runbook_steps_item import RegisterDRPlanRequestRunbookStepsItem


T = TypeVar("T", bound="RegisterDRPlanRequest")


@_attrs_define
class RegisterDRPlanRequest:
    """
    Attributes:
        name (str): DR plan name
        system_name (str): System this plan covers
        priority_order (int | Unset): Recovery priority (1 = highest) Default: 1.
        runbook_steps (list[RegisterDRPlanRequestRunbookStepsItem] | Unset):
        responsible_parties (list[str] | Unset):
        communication_plan (RegisterDRPlanRequestCommunicationPlan | Unset):
        rto_minutes (int | Unset):  Default: 480.
        rpo_minutes (int | Unset):  Default: 240.
        version (str | Unset):  Default: '1.0'.
        approved_by (None | str | Unset):
        next_review_at (None | str | Unset):
        tags (list[str] | Unset):
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    name: str
    system_name: str
    priority_order: int | Unset = 1
    runbook_steps: list[RegisterDRPlanRequestRunbookStepsItem] | Unset = UNSET
    responsible_parties: list[str] | Unset = UNSET
    communication_plan: RegisterDRPlanRequestCommunicationPlan | Unset = UNSET
    rto_minutes: int | Unset = 480
    rpo_minutes: int | Unset = 240
    version: str | Unset = "1.0"
    approved_by: None | str | Unset = UNSET
    next_review_at: None | str | Unset = UNSET
    tags: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        system_name = self.system_name

        priority_order = self.priority_order

        runbook_steps: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.runbook_steps, Unset):
            runbook_steps = []
            for runbook_steps_item_data in self.runbook_steps:
                runbook_steps_item = runbook_steps_item_data.to_dict()
                runbook_steps.append(runbook_steps_item)

        responsible_parties: list[str] | Unset = UNSET
        if not isinstance(self.responsible_parties, Unset):
            responsible_parties = self.responsible_parties

        communication_plan: dict[str, Any] | Unset = UNSET
        if not isinstance(self.communication_plan, Unset):
            communication_plan = self.communication_plan.to_dict()

        rto_minutes = self.rto_minutes

        rpo_minutes = self.rpo_minutes

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

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "system_name": system_name,
            }
        )
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
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.register_dr_plan_request_communication_plan import RegisterDRPlanRequestCommunicationPlan
        from ..models.register_dr_plan_request_runbook_steps_item import RegisterDRPlanRequestRunbookStepsItem

        d = dict(src_dict)
        name = d.pop("name")

        system_name = d.pop("system_name")

        priority_order = d.pop("priority_order", UNSET)

        _runbook_steps = d.pop("runbook_steps", UNSET)
        runbook_steps: list[RegisterDRPlanRequestRunbookStepsItem] | Unset = UNSET
        if _runbook_steps is not UNSET:
            runbook_steps = []
            for runbook_steps_item_data in _runbook_steps:
                runbook_steps_item = RegisterDRPlanRequestRunbookStepsItem.from_dict(runbook_steps_item_data)

                runbook_steps.append(runbook_steps_item)

        responsible_parties = cast(list[str], d.pop("responsible_parties", UNSET))

        _communication_plan = d.pop("communication_plan", UNSET)
        communication_plan: RegisterDRPlanRequestCommunicationPlan | Unset
        if isinstance(_communication_plan, Unset):
            communication_plan = UNSET
        else:
            communication_plan = RegisterDRPlanRequestCommunicationPlan.from_dict(_communication_plan)

        rto_minutes = d.pop("rto_minutes", UNSET)

        rpo_minutes = d.pop("rpo_minutes", UNSET)

        version = d.pop("version", UNSET)

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

        tags = cast(list[str], d.pop("tags", UNSET))

        org_id = d.pop("org_id", UNSET)

        register_dr_plan_request = cls(
            name=name,
            system_name=system_name,
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
            org_id=org_id,
        )

        register_dr_plan_request.additional_properties = d
        return register_dr_plan_request

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
