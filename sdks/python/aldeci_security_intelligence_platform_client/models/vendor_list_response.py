from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.vendor_response import VendorResponse


T = TypeVar("T", bound="VendorListResponse")


@_attrs_define
class VendorListResponse:
    """Paginated vendor registry response.

    Attributes:
        total (int):
        vendors (list[VendorResponse]):
    """

    total: int
    vendors: list[VendorResponse]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total = self.total

        vendors = []
        for vendors_item_data in self.vendors:
            vendors_item = vendors_item_data.to_dict()
            vendors.append(vendors_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total": total,
                "vendors": vendors,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vendor_response import VendorResponse

        d = dict(src_dict)
        total = d.pop("total")

        vendors = []
        _vendors = d.pop("vendors")
        for vendors_item_data in _vendors:
            vendors_item = VendorResponse.from_dict(vendors_item_data)

            vendors.append(vendors_item)

        vendor_list_response = cls(
            total=total,
            vendors=vendors,
        )

        vendor_list_response.additional_properties = d
        return vendor_list_response

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
