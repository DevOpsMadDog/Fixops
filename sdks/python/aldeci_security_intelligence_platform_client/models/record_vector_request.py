from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordVectorRequest")


@_attrs_define
class RecordVectorRequest:
    """
    Attributes:
        name (str): Short name for the threat vector
        vector_type (str | Unset): network | email | supply_chain | insider | physical | social_engineering | zero_day |
            credential_stuffing Default: 'network'.
        severity (str | Unset): critical | high | medium | low Default: 'medium'.
        description (None | str | Unset):
        frequency_score (float | None | Unset):  Default: 50.0.
        impact_score (float | None | Unset):  Default: 50.0.
        first_observed (None | str | Unset):
        last_observed (None | str | Unset):
    """

    name: str
    vector_type: str | Unset = "network"
    severity: str | Unset = "medium"
    description: None | str | Unset = UNSET
    frequency_score: float | None | Unset = 50.0
    impact_score: float | None | Unset = 50.0
    first_observed: None | str | Unset = UNSET
    last_observed: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        vector_type = self.vector_type

        severity = self.severity

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        frequency_score: float | None | Unset
        if isinstance(self.frequency_score, Unset):
            frequency_score = UNSET
        else:
            frequency_score = self.frequency_score

        impact_score: float | None | Unset
        if isinstance(self.impact_score, Unset):
            impact_score = UNSET
        else:
            impact_score = self.impact_score

        first_observed: None | str | Unset
        if isinstance(self.first_observed, Unset):
            first_observed = UNSET
        else:
            first_observed = self.first_observed

        last_observed: None | str | Unset
        if isinstance(self.last_observed, Unset):
            last_observed = UNSET
        else:
            last_observed = self.last_observed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if vector_type is not UNSET:
            field_dict["vector_type"] = vector_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if frequency_score is not UNSET:
            field_dict["frequency_score"] = frequency_score
        if impact_score is not UNSET:
            field_dict["impact_score"] = impact_score
        if first_observed is not UNSET:
            field_dict["first_observed"] = first_observed
        if last_observed is not UNSET:
            field_dict["last_observed"] = last_observed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        vector_type = d.pop("vector_type", UNSET)

        severity = d.pop("severity", UNSET)

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_frequency_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        frequency_score = _parse_frequency_score(d.pop("frequency_score", UNSET))

        def _parse_impact_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        impact_score = _parse_impact_score(d.pop("impact_score", UNSET))

        def _parse_first_observed(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_observed = _parse_first_observed(d.pop("first_observed", UNSET))

        def _parse_last_observed(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_observed = _parse_last_observed(d.pop("last_observed", UNSET))

        record_vector_request = cls(
            name=name,
            vector_type=vector_type,
            severity=severity,
            description=description,
            frequency_score=frequency_score,
            impact_score=impact_score,
            first_observed=first_observed,
            last_observed=last_observed,
        )

        record_vector_request.additional_properties = d
        return record_vector_request

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
