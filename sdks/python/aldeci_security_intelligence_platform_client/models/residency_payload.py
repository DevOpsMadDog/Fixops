from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ResidencyPayload")


@_attrs_define
class ResidencyPayload:
    """POST /residency/register — register a dataset for residency tracking.

    Attributes:
        dataset_name (str):
        data_categories (list[str]):
        storage_region (str):
        approved_regions (list[str] | None | Unset):
    """

    dataset_name: str
    data_categories: list[str]
    storage_region: str
    approved_regions: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dataset_name = self.dataset_name

        data_categories = self.data_categories

        storage_region = self.storage_region

        approved_regions: list[str] | None | Unset
        if isinstance(self.approved_regions, Unset):
            approved_regions = UNSET
        elif isinstance(self.approved_regions, list):
            approved_regions = self.approved_regions

        else:
            approved_regions = self.approved_regions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "dataset_name": dataset_name,
                "data_categories": data_categories,
                "storage_region": storage_region,
            }
        )
        if approved_regions is not UNSET:
            field_dict["approved_regions"] = approved_regions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        dataset_name = d.pop("dataset_name")

        data_categories = cast(list[str], d.pop("data_categories"))

        storage_region = d.pop("storage_region")

        def _parse_approved_regions(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                approved_regions_type_0 = cast(list[str], data)

                return approved_regions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        approved_regions = _parse_approved_regions(d.pop("approved_regions", UNSET))

        residency_payload = cls(
            dataset_name=dataset_name,
            data_categories=data_categories,
            storage_region=storage_region,
            approved_regions=approved_regions,
        )

        residency_payload.additional_properties = d
        return residency_payload

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
