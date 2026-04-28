from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.datapoint_create_tags import DatapointCreateTags


T = TypeVar("T", bound="DatapointCreate")


@_attrs_define
class DatapointCreate:
    """
    Attributes:
        telemetry_type (str | Unset): Type of telemetry metric Default: 'events_per_second'.
        source (str | Unset): siem/edr/ndr/firewall/ids/cloud/custom Default: 'siem'.
        value (float | Unset): Metric value Default: 0.0.
        unit (str | Unset): Unit of measurement Default: ''.
        tags (DatapointCreateTags | Unset): Optional tags
        collected_at (None | str | Unset): ISO 8601 collection timestamp
    """

    telemetry_type: str | Unset = "events_per_second"
    source: str | Unset = "siem"
    value: float | Unset = 0.0
    unit: str | Unset = ""
    tags: DatapointCreateTags | Unset = UNSET
    collected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        telemetry_type = self.telemetry_type

        source = self.source

        value = self.value

        unit = self.unit

        tags: dict[str, Any] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags.to_dict()

        collected_at: None | str | Unset
        if isinstance(self.collected_at, Unset):
            collected_at = UNSET
        else:
            collected_at = self.collected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if telemetry_type is not UNSET:
            field_dict["telemetry_type"] = telemetry_type
        if source is not UNSET:
            field_dict["source"] = source
        if value is not UNSET:
            field_dict["value"] = value
        if unit is not UNSET:
            field_dict["unit"] = unit
        if tags is not UNSET:
            field_dict["tags"] = tags
        if collected_at is not UNSET:
            field_dict["collected_at"] = collected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.datapoint_create_tags import DatapointCreateTags

        d = dict(src_dict)
        telemetry_type = d.pop("telemetry_type", UNSET)

        source = d.pop("source", UNSET)

        value = d.pop("value", UNSET)

        unit = d.pop("unit", UNSET)

        _tags = d.pop("tags", UNSET)
        tags: DatapointCreateTags | Unset
        if isinstance(_tags, Unset):
            tags = UNSET
        else:
            tags = DatapointCreateTags.from_dict(_tags)

        def _parse_collected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        collected_at = _parse_collected_at(d.pop("collected_at", UNSET))

        datapoint_create = cls(
            telemetry_type=telemetry_type,
            source=source,
            value=value,
            unit=unit,
            tags=tags,
            collected_at=collected_at,
        )

        datapoint_create.additional_properties = d
        return datapoint_create

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
