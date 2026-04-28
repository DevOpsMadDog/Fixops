from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ShadowITScanRequest")


@_attrs_define
class ShadowITScanRequest:
    """
    Attributes:
        org_id (str | Unset): Organisation ID Default: 'default'.
        cmdb_names (list[str] | None | Unset): Approved asset names from CMDB
        discovered_names (list[str] | None | Unset): Extra names from network discovery
    """

    org_id: str | Unset = "default"
    cmdb_names: list[str] | None | Unset = UNSET
    discovered_names: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        cmdb_names: list[str] | None | Unset
        if isinstance(self.cmdb_names, Unset):
            cmdb_names = UNSET
        elif isinstance(self.cmdb_names, list):
            cmdb_names = self.cmdb_names

        else:
            cmdb_names = self.cmdb_names

        discovered_names: list[str] | None | Unset
        if isinstance(self.discovered_names, Unset):
            discovered_names = UNSET
        elif isinstance(self.discovered_names, list):
            discovered_names = self.discovered_names

        else:
            discovered_names = self.discovered_names

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if cmdb_names is not UNSET:
            field_dict["cmdb_names"] = cmdb_names
        if discovered_names is not UNSET:
            field_dict["discovered_names"] = discovered_names

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        def _parse_cmdb_names(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                cmdb_names_type_0 = cast(list[str], data)

                return cmdb_names_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        cmdb_names = _parse_cmdb_names(d.pop("cmdb_names", UNSET))

        def _parse_discovered_names(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                discovered_names_type_0 = cast(list[str], data)

                return discovered_names_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        discovered_names = _parse_discovered_names(d.pop("discovered_names", UNSET))

        shadow_it_scan_request = cls(
            org_id=org_id,
            cmdb_names=cmdb_names,
            discovered_names=discovered_names,
        )

        shadow_it_scan_request.additional_properties = d
        return shadow_it_scan_request

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
