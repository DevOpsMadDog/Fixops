from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ModelStatusResponse")


@_attrs_define
class ModelStatusResponse:
    """Status of a single ML model.

    Attributes:
        name (str):
        type_ (str):
        status (str):
        samples_trained (int | Unset):  Default: 0.
        accuracy (float | Unset):  Default: 0.0.
        last_trained (None | str | Unset):
        feature_names (list[str] | Unset):
    """

    name: str
    type_: str
    status: str
    samples_trained: int | Unset = 0
    accuracy: float | Unset = 0.0
    last_trained: None | str | Unset = UNSET
    feature_names: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        type_ = self.type_

        status = self.status

        samples_trained = self.samples_trained

        accuracy = self.accuracy

        last_trained: None | str | Unset
        if isinstance(self.last_trained, Unset):
            last_trained = UNSET
        else:
            last_trained = self.last_trained

        feature_names: list[str] | Unset = UNSET
        if not isinstance(self.feature_names, Unset):
            feature_names = self.feature_names

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "type": type_,
                "status": status,
            }
        )
        if samples_trained is not UNSET:
            field_dict["samples_trained"] = samples_trained
        if accuracy is not UNSET:
            field_dict["accuracy"] = accuracy
        if last_trained is not UNSET:
            field_dict["last_trained"] = last_trained
        if feature_names is not UNSET:
            field_dict["feature_names"] = feature_names

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        type_ = d.pop("type")

        status = d.pop("status")

        samples_trained = d.pop("samples_trained", UNSET)

        accuracy = d.pop("accuracy", UNSET)

        def _parse_last_trained(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_trained = _parse_last_trained(d.pop("last_trained", UNSET))

        feature_names = cast(list[str], d.pop("feature_names", UNSET))

        model_status_response = cls(
            name=name,
            type_=type_,
            status=status,
            samples_trained=samples_trained,
            accuracy=accuracy,
            last_trained=last_trained,
            feature_names=feature_names,
        )

        model_status_response.additional_properties = d
        return model_status_response

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
