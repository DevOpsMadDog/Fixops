from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CompleteExperiment")


@_attrs_define
class CompleteExperiment:
    """
    Attributes:
        actual_outcome (str | Unset):  Default: ''.
        resilience_score (int | Unset):  Default: 0.
    """

    actual_outcome: str | Unset = ""
    resilience_score: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        actual_outcome = self.actual_outcome

        resilience_score = self.resilience_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if actual_outcome is not UNSET:
            field_dict["actual_outcome"] = actual_outcome
        if resilience_score is not UNSET:
            field_dict["resilience_score"] = resilience_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        actual_outcome = d.pop("actual_outcome", UNSET)

        resilience_score = d.pop("resilience_score", UNSET)

        complete_experiment = cls(
            actual_outcome=actual_outcome,
            resilience_score=resilience_score,
        )

        complete_experiment.additional_properties = d
        return complete_experiment

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
