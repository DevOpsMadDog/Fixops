from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MetricDefinitionCreate")


@_attrs_define
class MetricDefinitionCreate:
    """
    Attributes:
        name (str):
        description (str | Unset):  Default: ''.
        category (str | Unset):  Default: 'vulnerability'.
        unit (str | Unset):  Default: ''.
        target_value (float | None | Unset):
        critical_threshold (float | None | Unset):
        warning_threshold (float | None | Unset):
        enabled (int | Unset):  Default: 1.
    """

    name: str
    description: str | Unset = ""
    category: str | Unset = "vulnerability"
    unit: str | Unset = ""
    target_value: float | None | Unset = UNSET
    critical_threshold: float | None | Unset = UNSET
    warning_threshold: float | None | Unset = UNSET
    enabled: int | Unset = 1
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        category = self.category

        unit = self.unit

        target_value: float | None | Unset
        if isinstance(self.target_value, Unset):
            target_value = UNSET
        else:
            target_value = self.target_value

        critical_threshold: float | None | Unset
        if isinstance(self.critical_threshold, Unset):
            critical_threshold = UNSET
        else:
            critical_threshold = self.critical_threshold

        warning_threshold: float | None | Unset
        if isinstance(self.warning_threshold, Unset):
            warning_threshold = UNSET
        else:
            warning_threshold = self.warning_threshold

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if category is not UNSET:
            field_dict["category"] = category
        if unit is not UNSET:
            field_dict["unit"] = unit
        if target_value is not UNSET:
            field_dict["target_value"] = target_value
        if critical_threshold is not UNSET:
            field_dict["critical_threshold"] = critical_threshold
        if warning_threshold is not UNSET:
            field_dict["warning_threshold"] = warning_threshold
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description", UNSET)

        category = d.pop("category", UNSET)

        unit = d.pop("unit", UNSET)

        def _parse_target_value(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        target_value = _parse_target_value(d.pop("target_value", UNSET))

        def _parse_critical_threshold(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        critical_threshold = _parse_critical_threshold(d.pop("critical_threshold", UNSET))

        def _parse_warning_threshold(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        warning_threshold = _parse_warning_threshold(d.pop("warning_threshold", UNSET))

        enabled = d.pop("enabled", UNSET)

        metric_definition_create = cls(
            name=name,
            description=description,
            category=category,
            unit=unit,
            target_value=target_value,
            critical_threshold=critical_threshold,
            warning_threshold=warning_threshold,
            enabled=enabled,
        )

        metric_definition_create.additional_properties = d
        return metric_definition_create

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
