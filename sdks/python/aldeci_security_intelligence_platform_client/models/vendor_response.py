from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="VendorResponse")


@_attrs_define
class VendorResponse:
    """Vendor record with computed risk score.

    Attributes:
        id (str):
        name (str):
        service_category (str):
        data_access_level (str):
        is_core_operations (bool):
        tier (None | str):
        current_score (float | None):
        contract_start (str):
        contract_end (str):
        description (str):
        created_at (str):
        updated_at (str):
    """

    id: str
    name: str
    service_category: str
    data_access_level: str
    is_core_operations: bool
    tier: None | str
    current_score: float | None
    contract_start: str
    contract_end: str
    description: str
    created_at: str
    updated_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        service_category = self.service_category

        data_access_level = self.data_access_level

        is_core_operations = self.is_core_operations

        tier: None | str
        tier = self.tier

        current_score: float | None
        current_score = self.current_score

        contract_start = self.contract_start

        contract_end = self.contract_end

        description = self.description

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "service_category": service_category,
                "data_access_level": data_access_level,
                "is_core_operations": is_core_operations,
                "tier": tier,
                "current_score": current_score,
                "contract_start": contract_start,
                "contract_end": contract_end,
                "description": description,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        service_category = d.pop("service_category")

        data_access_level = d.pop("data_access_level")

        is_core_operations = d.pop("is_core_operations")

        def _parse_tier(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        tier = _parse_tier(d.pop("tier"))

        def _parse_current_score(data: object) -> float | None:
            if data is None:
                return data
            return cast(float | None, data)

        current_score = _parse_current_score(d.pop("current_score"))

        contract_start = d.pop("contract_start")

        contract_end = d.pop("contract_end")

        description = d.pop("description")

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        vendor_response = cls(
            id=id,
            name=name,
            service_category=service_category,
            data_access_level=data_access_level,
            is_core_operations=is_core_operations,
            tier=tier,
            current_score=current_score,
            contract_start=contract_start,
            contract_end=contract_end,
            description=description,
            created_at=created_at,
            updated_at=updated_at,
        )

        vendor_response.additional_properties = d
        return vendor_response

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
