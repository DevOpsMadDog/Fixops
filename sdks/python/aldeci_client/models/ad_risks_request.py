from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.ad_risks_request_ad_objects_item import ADRisksRequestAdObjectsItem


T = TypeVar("T", bound="ADRisksRequest")


@_attrs_define
class ADRisksRequest:
    """
    Attributes:
        ad_objects (list[ADRisksRequestAdObjectsItem]): List of AD/Entra object dicts (sAMAccountName, SPN, memberOf,
            uac, adminCount, ...)
    """

    ad_objects: list[ADRisksRequestAdObjectsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ad_objects = []
        for ad_objects_item_data in self.ad_objects:
            ad_objects_item = ad_objects_item_data.to_dict()
            ad_objects.append(ad_objects_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ad_objects": ad_objects,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ad_risks_request_ad_objects_item import ADRisksRequestAdObjectsItem

        d = dict(src_dict)
        ad_objects = []
        _ad_objects = d.pop("ad_objects")
        for ad_objects_item_data in _ad_objects:
            ad_objects_item = ADRisksRequestAdObjectsItem.from_dict(ad_objects_item_data)

            ad_objects.append(ad_objects_item)

        ad_risks_request = cls(
            ad_objects=ad_objects,
        )

        ad_risks_request.additional_properties = d
        return ad_risks_request

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
