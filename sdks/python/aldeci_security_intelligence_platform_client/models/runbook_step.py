from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RunbookStep")


@_attrs_define
class RunbookStep:
    """Single step in a DR runbook.

    Attributes:
        step_number (int):
        title (str):
        description (str):
        responsible_party (str):
        estimated_duration_minutes (int | Unset):  Default: 15.
        dependencies (list[int] | Unset):
        validation_criteria (None | str | Unset):
    """

    step_number: int
    title: str
    description: str
    responsible_party: str
    estimated_duration_minutes: int | Unset = 15
    dependencies: list[int] | Unset = UNSET
    validation_criteria: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        step_number = self.step_number

        title = self.title

        description = self.description

        responsible_party = self.responsible_party

        estimated_duration_minutes = self.estimated_duration_minutes

        dependencies: list[int] | Unset = UNSET
        if not isinstance(self.dependencies, Unset):
            dependencies = self.dependencies

        validation_criteria: None | str | Unset
        if isinstance(self.validation_criteria, Unset):
            validation_criteria = UNSET
        else:
            validation_criteria = self.validation_criteria

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "step_number": step_number,
                "title": title,
                "description": description,
                "responsible_party": responsible_party,
            }
        )
        if estimated_duration_minutes is not UNSET:
            field_dict["estimated_duration_minutes"] = estimated_duration_minutes
        if dependencies is not UNSET:
            field_dict["dependencies"] = dependencies
        if validation_criteria is not UNSET:
            field_dict["validation_criteria"] = validation_criteria

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        step_number = d.pop("step_number")

        title = d.pop("title")

        description = d.pop("description")

        responsible_party = d.pop("responsible_party")

        estimated_duration_minutes = d.pop("estimated_duration_minutes", UNSET)

        dependencies = cast(list[int], d.pop("dependencies", UNSET))

        def _parse_validation_criteria(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        validation_criteria = _parse_validation_criteria(d.pop("validation_criteria", UNSET))

        runbook_step = cls(
            step_number=step_number,
            title=title,
            description=description,
            responsible_party=responsible_party,
            estimated_duration_minutes=estimated_duration_minutes,
            dependencies=dependencies,
            validation_criteria=validation_criteria,
        )

        runbook_step.additional_properties = d
        return runbook_step

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
