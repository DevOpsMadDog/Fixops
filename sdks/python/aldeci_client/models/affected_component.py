from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AffectedComponent")


@_attrs_define
class AffectedComponent:
    """Affected software/hardware component.

    Attributes:
        vendor (str):
        product (str):
        version (str):
        version_end (None | str | Unset):
        cpe (None | str | Unset): CPE identifier if known
    """

    vendor: str
    product: str
    version: str
    version_end: None | str | Unset = UNSET
    cpe: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vendor = self.vendor

        product = self.product

        version = self.version

        version_end: None | str | Unset
        if isinstance(self.version_end, Unset):
            version_end = UNSET
        else:
            version_end = self.version_end

        cpe: None | str | Unset
        if isinstance(self.cpe, Unset):
            cpe = UNSET
        else:
            cpe = self.cpe

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor": vendor,
                "product": product,
                "version": version,
            }
        )
        if version_end is not UNSET:
            field_dict["version_end"] = version_end
        if cpe is not UNSET:
            field_dict["cpe"] = cpe

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vendor = d.pop("vendor")

        product = d.pop("product")

        version = d.pop("version")

        def _parse_version_end(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version_end = _parse_version_end(d.pop("version_end", UNSET))

        def _parse_cpe(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cpe = _parse_cpe(d.pop("cpe", UNSET))

        affected_component = cls(
            vendor=vendor,
            product=product,
            version=version,
            version_end=version_end,
            cpe=cpe,
        )

        affected_component.additional_properties = d
        return affected_component

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
