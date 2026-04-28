from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BulkLookupRequest")


@_attrs_define
class BulkLookupRequest:
    """
    Attributes:
        values (list[str]):
        ioc_type (None | str | Unset):
    """

    values: list[str]
    ioc_type: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        values = self.values

        ioc_type: None | str | Unset
        if isinstance(self.ioc_type, Unset):
            ioc_type = UNSET
        else:
            ioc_type = self.ioc_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "values": values,
            }
        )
        if ioc_type is not UNSET:
            field_dict["ioc_type"] = ioc_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        values = cast(list[str], d.pop("values"))

        def _parse_ioc_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ioc_type = _parse_ioc_type(d.pop("ioc_type", UNSET))

        bulk_lookup_request = cls(
            values=values,
            ioc_type=ioc_type,
        )

        bulk_lookup_request.additional_properties = d
        return bulk_lookup_request

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
