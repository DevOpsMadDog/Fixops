from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExperimentCreate")


@_attrs_define
class ExperimentCreate:
    """
    Attributes:
        experiment_name (str):
        experiment_type (str):
        target_system (str):
        hypothesis (str | Unset):  Default: ''.
        expected_outcome (str | Unset):  Default: ''.
        scheduled_at (None | str | Unset):
    """

    experiment_name: str
    experiment_type: str
    target_system: str
    hypothesis: str | Unset = ""
    expected_outcome: str | Unset = ""
    scheduled_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        experiment_name = self.experiment_name

        experiment_type = self.experiment_type

        target_system = self.target_system

        hypothesis = self.hypothesis

        expected_outcome = self.expected_outcome

        scheduled_at: None | str | Unset
        if isinstance(self.scheduled_at, Unset):
            scheduled_at = UNSET
        else:
            scheduled_at = self.scheduled_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "experiment_name": experiment_name,
                "experiment_type": experiment_type,
                "target_system": target_system,
            }
        )
        if hypothesis is not UNSET:
            field_dict["hypothesis"] = hypothesis
        if expected_outcome is not UNSET:
            field_dict["expected_outcome"] = expected_outcome
        if scheduled_at is not UNSET:
            field_dict["scheduled_at"] = scheduled_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        experiment_name = d.pop("experiment_name")

        experiment_type = d.pop("experiment_type")

        target_system = d.pop("target_system")

        hypothesis = d.pop("hypothesis", UNSET)

        expected_outcome = d.pop("expected_outcome", UNSET)

        def _parse_scheduled_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scheduled_at = _parse_scheduled_at(d.pop("scheduled_at", UNSET))

        experiment_create = cls(
            experiment_name=experiment_name,
            experiment_type=experiment_type,
            target_system=target_system,
            hypothesis=hypothesis,
            expected_outcome=expected_outcome,
            scheduled_at=scheduled_at,
        )

        experiment_create.additional_properties = d
        return experiment_create

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
