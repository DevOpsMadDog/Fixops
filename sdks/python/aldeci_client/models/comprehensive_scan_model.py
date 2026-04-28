from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ComprehensiveScanModel")


@_attrs_define
class ComprehensiveScanModel:
    """Model for comprehensive scan.

    Attributes:
        target (str):
        scan_types (list[str] | None | Unset):
        scan_type (None | str | Unset):  Default: 'comprehensive'.
        depth (None | str | Unset):  Default: 'standard'.
    """

    target: str
    scan_types: list[str] | None | Unset = UNSET
    scan_type: None | str | Unset = "comprehensive"
    depth: None | str | Unset = "standard"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target = self.target

        scan_types: list[str] | None | Unset
        if isinstance(self.scan_types, Unset):
            scan_types = UNSET
        elif isinstance(self.scan_types, list):
            scan_types = self.scan_types

        else:
            scan_types = self.scan_types

        scan_type: None | str | Unset
        if isinstance(self.scan_type, Unset):
            scan_type = UNSET
        else:
            scan_type = self.scan_type

        depth: None | str | Unset
        if isinstance(self.depth, Unset):
            depth = UNSET
        else:
            depth = self.depth

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "target": target,
            }
        )
        if scan_types is not UNSET:
            field_dict["scan_types"] = scan_types
        if scan_type is not UNSET:
            field_dict["scan_type"] = scan_type
        if depth is not UNSET:
            field_dict["depth"] = depth

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target = d.pop("target")

        def _parse_scan_types(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                scan_types_type_0 = cast(list[str], data)

                return scan_types_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        scan_types = _parse_scan_types(d.pop("scan_types", UNSET))

        def _parse_scan_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scan_type = _parse_scan_type(d.pop("scan_type", UNSET))

        def _parse_depth(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        depth = _parse_depth(d.pop("depth", UNSET))

        comprehensive_scan_model = cls(
            target=target,
            scan_types=scan_types,
            scan_type=scan_type,
            depth=depth,
        )

        comprehensive_scan_model.additional_properties = d
        return comprehensive_scan_model

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
