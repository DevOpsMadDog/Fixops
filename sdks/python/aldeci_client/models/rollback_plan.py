from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RollbackPlan")


@_attrs_define
class RollbackPlan:
    """Rollback plan for a change request.

    Attributes:
        steps (list[str]): Ordered rollback steps
        responsible_person (str): Person responsible for executing rollback
        validation_criteria (list[str] | Unset): Criteria to confirm rollback success
        max_rollback_time_minutes (int | Unset): Maximum time allowed for rollback in minutes Default: 60.
        automated (bool | Unset): Whether rollback can be automated Default: False.
        rollback_script (None | str | Unset): Script to execute for automated rollback
    """

    steps: list[str]
    responsible_person: str
    validation_criteria: list[str] | Unset = UNSET
    max_rollback_time_minutes: int | Unset = 60
    automated: bool | Unset = False
    rollback_script: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        steps = self.steps

        responsible_person = self.responsible_person

        validation_criteria: list[str] | Unset = UNSET
        if not isinstance(self.validation_criteria, Unset):
            validation_criteria = self.validation_criteria

        max_rollback_time_minutes = self.max_rollback_time_minutes

        automated = self.automated

        rollback_script: None | str | Unset
        if isinstance(self.rollback_script, Unset):
            rollback_script = UNSET
        else:
            rollback_script = self.rollback_script

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "steps": steps,
                "responsible_person": responsible_person,
            }
        )
        if validation_criteria is not UNSET:
            field_dict["validation_criteria"] = validation_criteria
        if max_rollback_time_minutes is not UNSET:
            field_dict["max_rollback_time_minutes"] = max_rollback_time_minutes
        if automated is not UNSET:
            field_dict["automated"] = automated
        if rollback_script is not UNSET:
            field_dict["rollback_script"] = rollback_script

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        steps = cast(list[str], d.pop("steps"))

        responsible_person = d.pop("responsible_person")

        validation_criteria = cast(list[str], d.pop("validation_criteria", UNSET))

        max_rollback_time_minutes = d.pop("max_rollback_time_minutes", UNSET)

        automated = d.pop("automated", UNSET)

        def _parse_rollback_script(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        rollback_script = _parse_rollback_script(d.pop("rollback_script", UNSET))

        rollback_plan = cls(
            steps=steps,
            responsible_person=responsible_person,
            validation_criteria=validation_criteria,
            max_rollback_time_minutes=max_rollback_time_minutes,
            automated=automated,
            rollback_script=rollback_script,
        )

        rollback_plan.additional_properties = d
        return rollback_plan

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
