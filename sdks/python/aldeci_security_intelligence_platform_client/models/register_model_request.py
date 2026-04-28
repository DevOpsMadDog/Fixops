from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterModelRequest")


@_attrs_define
class RegisterModelRequest:
    """
    Attributes:
        model_name (str): Human-readable model name
        model_type (str | Unset): anomaly_detection | classification | nlp | graph_ml | time_series | ensemble Default:
            'anomaly_detection'.
        accuracy_score (float | Unset):  Default: 0.0.
        false_positive_rate (float | Unset):  Default: 0.0.
        version (str | Unset):  Default: '1.0'.
        training_data_size (int | Unset):  Default: 0.
        deployed_at (None | str | Unset):
        last_retrained (None | str | Unset):
    """

    model_name: str
    model_type: str | Unset = "anomaly_detection"
    accuracy_score: float | Unset = 0.0
    false_positive_rate: float | Unset = 0.0
    version: str | Unset = "1.0"
    training_data_size: int | Unset = 0
    deployed_at: None | str | Unset = UNSET
    last_retrained: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        model_name = self.model_name

        model_type = self.model_type

        accuracy_score = self.accuracy_score

        false_positive_rate = self.false_positive_rate

        version = self.version

        training_data_size = self.training_data_size

        deployed_at: None | str | Unset
        if isinstance(self.deployed_at, Unset):
            deployed_at = UNSET
        else:
            deployed_at = self.deployed_at

        last_retrained: None | str | Unset
        if isinstance(self.last_retrained, Unset):
            last_retrained = UNSET
        else:
            last_retrained = self.last_retrained

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "model_name": model_name,
            }
        )
        if model_type is not UNSET:
            field_dict["model_type"] = model_type
        if accuracy_score is not UNSET:
            field_dict["accuracy_score"] = accuracy_score
        if false_positive_rate is not UNSET:
            field_dict["false_positive_rate"] = false_positive_rate
        if version is not UNSET:
            field_dict["version"] = version
        if training_data_size is not UNSET:
            field_dict["training_data_size"] = training_data_size
        if deployed_at is not UNSET:
            field_dict["deployed_at"] = deployed_at
        if last_retrained is not UNSET:
            field_dict["last_retrained"] = last_retrained

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        model_name = d.pop("model_name")

        model_type = d.pop("model_type", UNSET)

        accuracy_score = d.pop("accuracy_score", UNSET)

        false_positive_rate = d.pop("false_positive_rate", UNSET)

        version = d.pop("version", UNSET)

        training_data_size = d.pop("training_data_size", UNSET)

        def _parse_deployed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        deployed_at = _parse_deployed_at(d.pop("deployed_at", UNSET))

        def _parse_last_retrained(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_retrained = _parse_last_retrained(d.pop("last_retrained", UNSET))

        register_model_request = cls(
            model_name=model_name,
            model_type=model_type,
            accuracy_score=accuracy_score,
            false_positive_rate=false_positive_rate,
            version=version,
            training_data_size=training_data_size,
            deployed_at=deployed_at,
            last_retrained=last_retrained,
        )

        register_model_request.additional_properties = d
        return register_model_request

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
