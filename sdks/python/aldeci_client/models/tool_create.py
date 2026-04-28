from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ToolCreate")


@_attrs_define
class ToolCreate:
    """
    Attributes:
        tool_name (str):
        tool_category (str | Unset):  Default: 'detection'.
        vendor (str | Unset):  Default: ''.
        cloud_provider (str | Unset):  Default: 'multi-cloud'.
        monthly_cost (float | Unset):  Default: 0.0.
        licenses (int | Unset):  Default: 0.
    """

    tool_name: str
    tool_category: str | Unset = "detection"
    vendor: str | Unset = ""
    cloud_provider: str | Unset = "multi-cloud"
    monthly_cost: float | Unset = 0.0
    licenses: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tool_name = self.tool_name

        tool_category = self.tool_category

        vendor = self.vendor

        cloud_provider = self.cloud_provider

        monthly_cost = self.monthly_cost

        licenses = self.licenses

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tool_name": tool_name,
            }
        )
        if tool_category is not UNSET:
            field_dict["tool_category"] = tool_category
        if vendor is not UNSET:
            field_dict["vendor"] = vendor
        if cloud_provider is not UNSET:
            field_dict["cloud_provider"] = cloud_provider
        if monthly_cost is not UNSET:
            field_dict["monthly_cost"] = monthly_cost
        if licenses is not UNSET:
            field_dict["licenses"] = licenses

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tool_name = d.pop("tool_name")

        tool_category = d.pop("tool_category", UNSET)

        vendor = d.pop("vendor", UNSET)

        cloud_provider = d.pop("cloud_provider", UNSET)

        monthly_cost = d.pop("monthly_cost", UNSET)

        licenses = d.pop("licenses", UNSET)

        tool_create = cls(
            tool_name=tool_name,
            tool_category=tool_category,
            vendor=vendor,
            cloud_provider=cloud_provider,
            monthly_cost=monthly_cost,
            licenses=licenses,
        )

        tool_create.additional_properties = d
        return tool_create

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
