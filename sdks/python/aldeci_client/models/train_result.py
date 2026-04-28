from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TrainResult")


@_attrs_define
class TrainResult:
    """Training result for a model.

    Attributes:
        name (str):
        status (str):
        samples_trained (int | Unset):  Default: 0.
        accuracy (float | Unset):  Default: 0.0.
    """

    name: str
    status: str
    samples_trained: int | Unset = 0
    accuracy: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        status = self.status

        samples_trained = self.samples_trained

        accuracy = self.accuracy

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "status": status,
            }
        )
        if samples_trained is not UNSET:
            field_dict["samples_trained"] = samples_trained
        if accuracy is not UNSET:
            field_dict["accuracy"] = accuracy

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        status = d.pop("status")

        samples_trained = d.pop("samples_trained", UNSET)

        accuracy = d.pop("accuracy", UNSET)

        train_result = cls(
            name=name,
            status=status,
            samples_trained=samples_trained,
            accuracy=accuracy,
        )

        train_result.additional_properties = d
        return train_result

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
