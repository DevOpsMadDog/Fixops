from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.change_category import ChangeCategory
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.impact_analysis import ImpactAnalysis
    from ..models.rollback_plan import RollbackPlan


T = TypeVar("T", bound="CreateChangeRequest")


@_attrs_define
class CreateChangeRequest:
    """
    Attributes:
        title (str):
        description (str):
        category (ChangeCategory):
        requestor_id (str):
        requestor_name (str):
        rollback_plan (RollbackPlan): Rollback plan for a change request.
        requestor_team (None | str | Unset):
        impact_analysis (ImpactAnalysis | None | Unset):
        scheduled_start (datetime.datetime | None | Unset):
        scheduled_end (datetime.datetime | None | Unset):
        priority (str | Unset):  Default: 'medium'.
        tags (list[str] | Unset):
        external_ticket_id (None | str | Unset):
    """

    title: str
    description: str
    category: ChangeCategory
    requestor_id: str
    requestor_name: str
    rollback_plan: RollbackPlan
    requestor_team: None | str | Unset = UNSET
    impact_analysis: ImpactAnalysis | None | Unset = UNSET
    scheduled_start: datetime.datetime | None | Unset = UNSET
    scheduled_end: datetime.datetime | None | Unset = UNSET
    priority: str | Unset = "medium"
    tags: list[str] | Unset = UNSET
    external_ticket_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.impact_analysis import ImpactAnalysis

        title = self.title

        description = self.description

        category = self.category.value

        requestor_id = self.requestor_id

        requestor_name = self.requestor_name

        rollback_plan = self.rollback_plan.to_dict()

        requestor_team: None | str | Unset
        if isinstance(self.requestor_team, Unset):
            requestor_team = UNSET
        else:
            requestor_team = self.requestor_team

        impact_analysis: dict[str, Any] | None | Unset
        if isinstance(self.impact_analysis, Unset):
            impact_analysis = UNSET
        elif isinstance(self.impact_analysis, ImpactAnalysis):
            impact_analysis = self.impact_analysis.to_dict()
        else:
            impact_analysis = self.impact_analysis

        scheduled_start: None | str | Unset
        if isinstance(self.scheduled_start, Unset):
            scheduled_start = UNSET
        elif isinstance(self.scheduled_start, datetime.datetime):
            scheduled_start = self.scheduled_start.isoformat()
        else:
            scheduled_start = self.scheduled_start

        scheduled_end: None | str | Unset
        if isinstance(self.scheduled_end, Unset):
            scheduled_end = UNSET
        elif isinstance(self.scheduled_end, datetime.datetime):
            scheduled_end = self.scheduled_end.isoformat()
        else:
            scheduled_end = self.scheduled_end

        priority = self.priority

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        external_ticket_id: None | str | Unset
        if isinstance(self.external_ticket_id, Unset):
            external_ticket_id = UNSET
        else:
            external_ticket_id = self.external_ticket_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "description": description,
                "category": category,
                "requestor_id": requestor_id,
                "requestor_name": requestor_name,
                "rollback_plan": rollback_plan,
            }
        )
        if requestor_team is not UNSET:
            field_dict["requestor_team"] = requestor_team
        if impact_analysis is not UNSET:
            field_dict["impact_analysis"] = impact_analysis
        if scheduled_start is not UNSET:
            field_dict["scheduled_start"] = scheduled_start
        if scheduled_end is not UNSET:
            field_dict["scheduled_end"] = scheduled_end
        if priority is not UNSET:
            field_dict["priority"] = priority
        if tags is not UNSET:
            field_dict["tags"] = tags
        if external_ticket_id is not UNSET:
            field_dict["external_ticket_id"] = external_ticket_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.impact_analysis import ImpactAnalysis
        from ..models.rollback_plan import RollbackPlan

        d = dict(src_dict)
        title = d.pop("title")

        description = d.pop("description")

        category = ChangeCategory(d.pop("category"))

        requestor_id = d.pop("requestor_id")

        requestor_name = d.pop("requestor_name")

        rollback_plan = RollbackPlan.from_dict(d.pop("rollback_plan"))

        def _parse_requestor_team(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        requestor_team = _parse_requestor_team(d.pop("requestor_team", UNSET))

        def _parse_impact_analysis(data: object) -> ImpactAnalysis | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                impact_analysis_type_0 = ImpactAnalysis.from_dict(data)

                return impact_analysis_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ImpactAnalysis | None | Unset, data)

        impact_analysis = _parse_impact_analysis(d.pop("impact_analysis", UNSET))

        def _parse_scheduled_start(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                scheduled_start_type_0 = isoparse(data)

                return scheduled_start_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        scheduled_start = _parse_scheduled_start(d.pop("scheduled_start", UNSET))

        def _parse_scheduled_end(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                scheduled_end_type_0 = isoparse(data)

                return scheduled_end_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        scheduled_end = _parse_scheduled_end(d.pop("scheduled_end", UNSET))

        priority = d.pop("priority", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        def _parse_external_ticket_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        external_ticket_id = _parse_external_ticket_id(d.pop("external_ticket_id", UNSET))

        create_change_request = cls(
            title=title,
            description=description,
            category=category,
            requestor_id=requestor_id,
            requestor_name=requestor_name,
            rollback_plan=rollback_plan,
            requestor_team=requestor_team,
            impact_analysis=impact_analysis,
            scheduled_start=scheduled_start,
            scheduled_end=scheduled_end,
            priority=priority,
            tags=tags,
            external_ticket_id=external_ticket_id,
        )

        create_change_request.additional_properties = d
        return create_change_request

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
