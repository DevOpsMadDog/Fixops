from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateExerciseRequest")


@_attrs_define
class CreateExerciseRequest:
    """
    Attributes:
        name (str): Exercise name
        scenario_id (str): Pre-built scenario ID (e.g. sc-001)
        description (str | Unset): Optional exercise description Default: ''.
        scope (str | Unset): Exercise scope: full, edr_only, network, cloud, identity Default: 'full'.
        red_team_lead (str | Unset): Red team lead identifier Default: 'red_team'.
        blue_team_lead (str | Unset): Blue team lead identifier Default: 'blue_team'.
        scheduled_at (None | str | Unset): ISO-8601 scheduled start time
        tags (list[str] | Unset): Arbitrary tags
    """

    name: str
    scenario_id: str
    description: str | Unset = ""
    scope: str | Unset = "full"
    red_team_lead: str | Unset = "red_team"
    blue_team_lead: str | Unset = "blue_team"
    scheduled_at: None | str | Unset = UNSET
    tags: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        scenario_id = self.scenario_id

        description = self.description

        scope = self.scope

        red_team_lead = self.red_team_lead

        blue_team_lead = self.blue_team_lead

        scheduled_at: None | str | Unset
        if isinstance(self.scheduled_at, Unset):
            scheduled_at = UNSET
        else:
            scheduled_at = self.scheduled_at

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "scenario_id": scenario_id,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if scope is not UNSET:
            field_dict["scope"] = scope
        if red_team_lead is not UNSET:
            field_dict["red_team_lead"] = red_team_lead
        if blue_team_lead is not UNSET:
            field_dict["blue_team_lead"] = blue_team_lead
        if scheduled_at is not UNSET:
            field_dict["scheduled_at"] = scheduled_at
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        scenario_id = d.pop("scenario_id")

        description = d.pop("description", UNSET)

        scope = d.pop("scope", UNSET)

        red_team_lead = d.pop("red_team_lead", UNSET)

        blue_team_lead = d.pop("blue_team_lead", UNSET)

        def _parse_scheduled_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scheduled_at = _parse_scheduled_at(d.pop("scheduled_at", UNSET))

        tags = cast(list[str], d.pop("tags", UNSET))

        create_exercise_request = cls(
            name=name,
            scenario_id=scenario_id,
            description=description,
            scope=scope,
            red_team_lead=red_team_lead,
            blue_team_lead=blue_team_lead,
            scheduled_at=scheduled_at,
            tags=tags,
        )

        create_exercise_request.additional_properties = d
        return create_exercise_request

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
