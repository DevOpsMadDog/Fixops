from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateDeliveryRequest")


@_attrs_define
class CreateDeliveryRequest:
    """
    Attributes:
        delivery_type (str):
        endpoint (str | Unset):  Default: ''.
        filter_severity (str | Unset):  Default: 'all'.
        filter_categories (list[str] | Unset):
    """

    delivery_type: str
    endpoint: str | Unset = ""
    filter_severity: str | Unset = "all"
    filter_categories: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        delivery_type = self.delivery_type

        endpoint = self.endpoint

        filter_severity = self.filter_severity

        filter_categories: list[str] | Unset = UNSET
        if not isinstance(self.filter_categories, Unset):
            filter_categories = self.filter_categories

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "delivery_type": delivery_type,
            }
        )
        if endpoint is not UNSET:
            field_dict["endpoint"] = endpoint
        if filter_severity is not UNSET:
            field_dict["filter_severity"] = filter_severity
        if filter_categories is not UNSET:
            field_dict["filter_categories"] = filter_categories

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        delivery_type = d.pop("delivery_type")

        endpoint = d.pop("endpoint", UNSET)

        filter_severity = d.pop("filter_severity", UNSET)

        filter_categories = cast(list[str], d.pop("filter_categories", UNSET))

        create_delivery_request = cls(
            delivery_type=delivery_type,
            endpoint=endpoint,
            filter_severity=filter_severity,
            filter_categories=filter_categories,
        )

        create_delivery_request.additional_properties = d
        return create_delivery_request

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
