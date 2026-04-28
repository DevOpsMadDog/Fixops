from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReadingCreate")


@_attrs_define
class ReadingCreate:
    """
    Attributes:
        value (float):
        source_system (str | Unset):  Default: 'manual'.
        period_start (None | str | Unset):
        period_end (None | str | Unset):
    """

    value: float
    source_system: str | Unset = "manual"
    period_start: None | str | Unset = UNSET
    period_end: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = self.value

        source_system = self.source_system

        period_start: None | str | Unset
        if isinstance(self.period_start, Unset):
            period_start = UNSET
        else:
            period_start = self.period_start

        period_end: None | str | Unset
        if isinstance(self.period_end, Unset):
            period_end = UNSET
        else:
            period_end = self.period_end

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "value": value,
            }
        )
        if source_system is not UNSET:
            field_dict["source_system"] = source_system
        if period_start is not UNSET:
            field_dict["period_start"] = period_start
        if period_end is not UNSET:
            field_dict["period_end"] = period_end

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        value = d.pop("value")

        source_system = d.pop("source_system", UNSET)

        def _parse_period_start(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        period_start = _parse_period_start(d.pop("period_start", UNSET))

        def _parse_period_end(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        period_end = _parse_period_end(d.pop("period_end", UNSET))

        reading_create = cls(
            value=value,
            source_system=source_system,
            period_start=period_start,
            period_end=period_end,
        )

        reading_create.additional_properties = d
        return reading_create

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
