from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VersionRangeModel")


@_attrs_define
class VersionRangeModel:
    """
    Attributes:
        product (str):
        min_version (None | str | Unset):
        max_version (None | str | Unset):
        fixed_version (None | str | Unset):
        version_regex (str | Unset):  Default: ''.
        extract_from (str | Unset):  Default: 'header'.
    """

    product: str
    min_version: None | str | Unset = UNSET
    max_version: None | str | Unset = UNSET
    fixed_version: None | str | Unset = UNSET
    version_regex: str | Unset = ""
    extract_from: str | Unset = "header"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        product = self.product

        min_version: None | str | Unset
        if isinstance(self.min_version, Unset):
            min_version = UNSET
        else:
            min_version = self.min_version

        max_version: None | str | Unset
        if isinstance(self.max_version, Unset):
            max_version = UNSET
        else:
            max_version = self.max_version

        fixed_version: None | str | Unset
        if isinstance(self.fixed_version, Unset):
            fixed_version = UNSET
        else:
            fixed_version = self.fixed_version

        version_regex = self.version_regex

        extract_from = self.extract_from

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "product": product,
            }
        )
        if min_version is not UNSET:
            field_dict["min_version"] = min_version
        if max_version is not UNSET:
            field_dict["max_version"] = max_version
        if fixed_version is not UNSET:
            field_dict["fixed_version"] = fixed_version
        if version_regex is not UNSET:
            field_dict["version_regex"] = version_regex
        if extract_from is not UNSET:
            field_dict["extract_from"] = extract_from

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        product = d.pop("product")

        def _parse_min_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        min_version = _parse_min_version(d.pop("min_version", UNSET))

        def _parse_max_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        max_version = _parse_max_version(d.pop("max_version", UNSET))

        def _parse_fixed_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fixed_version = _parse_fixed_version(d.pop("fixed_version", UNSET))

        version_regex = d.pop("version_regex", UNSET)

        extract_from = d.pop("extract_from", UNSET)

        version_range_model = cls(
            product=product,
            min_version=min_version,
            max_version=max_version,
            fixed_version=fixed_version,
            version_regex=version_regex,
            extract_from=extract_from,
        )

        version_range_model.additional_properties = d
        return version_range_model

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
