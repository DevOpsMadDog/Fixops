from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.ioc import IOC


T = TypeVar("T", bound="IOCListResponse")


@_attrs_define
class IOCListResponse:
    """
    Attributes:
        iocs (list[IOC]):
        total (int):
    """

    iocs: list[IOC]
    total: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        iocs = []
        for iocs_item_data in self.iocs:
            iocs_item = iocs_item_data.to_dict()
            iocs.append(iocs_item)

        total = self.total

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "iocs": iocs,
                "total": total,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ioc import IOC

        d = dict(src_dict)
        iocs = []
        _iocs = d.pop("iocs")
        for iocs_item_data in _iocs:
            iocs_item = IOC.from_dict(iocs_item_data)

            iocs.append(iocs_item)

        total = d.pop("total")

        ioc_list_response = cls(
            iocs=iocs,
            total=total,
        )

        ioc_list_response.additional_properties = d
        return ioc_list_response

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
