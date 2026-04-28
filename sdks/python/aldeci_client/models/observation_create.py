from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ObservationCreate")


@_attrs_define
class ObservationCreate:
    """
    Attributes:
        observation_type (str):
        severity (str | Unset):  Default: 'info'.
        description (str | Unset):  Default: ''.
        observed_at (None | str | Unset):
    """

    observation_type: str
    severity: str | Unset = "info"
    description: str | Unset = ""
    observed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        observation_type = self.observation_type

        severity = self.severity

        description = self.description

        observed_at: None | str | Unset
        if isinstance(self.observed_at, Unset):
            observed_at = UNSET
        else:
            observed_at = self.observed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "observation_type": observation_type,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if observed_at is not UNSET:
            field_dict["observed_at"] = observed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        observation_type = d.pop("observation_type")

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        def _parse_observed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        observed_at = _parse_observed_at(d.pop("observed_at", UNSET))

        observation_create = cls(
            observation_type=observation_type,
            severity=severity,
            description=description,
            observed_at=observed_at,
        )

        observation_create.additional_properties = d
        return observation_create

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
