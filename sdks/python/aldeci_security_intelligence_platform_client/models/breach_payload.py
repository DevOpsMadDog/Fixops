from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BreachPayload")


@_attrs_define
class BreachPayload:
    """POST /breach-impact — assess regulatory impact of a breach.

    Attributes:
        estimated_records (int):
        data_categories (list[str]):
        breach_id (None | str | Unset):
        affected_systems (list[str] | Unset):
        storage_regions (list[str] | None | Unset):
        discovery_date (None | str | Unset):
    """

    estimated_records: int
    data_categories: list[str]
    breach_id: None | str | Unset = UNSET
    affected_systems: list[str] | Unset = UNSET
    storage_regions: list[str] | None | Unset = UNSET
    discovery_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        estimated_records = self.estimated_records

        data_categories = self.data_categories

        breach_id: None | str | Unset
        if isinstance(self.breach_id, Unset):
            breach_id = UNSET
        else:
            breach_id = self.breach_id

        affected_systems: list[str] | Unset = UNSET
        if not isinstance(self.affected_systems, Unset):
            affected_systems = self.affected_systems

        storage_regions: list[str] | None | Unset
        if isinstance(self.storage_regions, Unset):
            storage_regions = UNSET
        elif isinstance(self.storage_regions, list):
            storage_regions = self.storage_regions

        else:
            storage_regions = self.storage_regions

        discovery_date: None | str | Unset
        if isinstance(self.discovery_date, Unset):
            discovery_date = UNSET
        else:
            discovery_date = self.discovery_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "estimated_records": estimated_records,
                "data_categories": data_categories,
            }
        )
        if breach_id is not UNSET:
            field_dict["breach_id"] = breach_id
        if affected_systems is not UNSET:
            field_dict["affected_systems"] = affected_systems
        if storage_regions is not UNSET:
            field_dict["storage_regions"] = storage_regions
        if discovery_date is not UNSET:
            field_dict["discovery_date"] = discovery_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        estimated_records = d.pop("estimated_records")

        data_categories = cast(list[str], d.pop("data_categories"))

        def _parse_breach_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        breach_id = _parse_breach_id(d.pop("breach_id", UNSET))

        affected_systems = cast(list[str], d.pop("affected_systems", UNSET))

        def _parse_storage_regions(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                storage_regions_type_0 = cast(list[str], data)

                return storage_regions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        storage_regions = _parse_storage_regions(d.pop("storage_regions", UNSET))

        def _parse_discovery_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        discovery_date = _parse_discovery_date(d.pop("discovery_date", UNSET))

        breach_payload = cls(
            estimated_records=estimated_records,
            data_categories=data_categories,
            breach_id=breach_id,
            affected_systems=affected_systems,
            storage_regions=storage_regions,
            discovery_date=discovery_date,
        )

        breach_payload.additional_properties = d
        return breach_payload

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
