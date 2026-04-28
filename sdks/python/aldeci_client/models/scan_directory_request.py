from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanDirectoryRequest")


@_attrs_define
class ScanDirectoryRequest:
    """Request body for scanning a directory.

    Attributes:
        path (str): Absolute or relative filesystem path to scan
        rules (None | str | Unset): Semgrep ruleset or config, e.g. p/security-audit. Defaults to p/default.
        org_id (str | Unset): Organisation identifier Default: 'default'.
    """

    path: str
    rules: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        path = self.path

        rules: None | str | Unset
        if isinstance(self.rules, Unset):
            rules = UNSET
        else:
            rules = self.rules

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "path": path,
            }
        )
        if rules is not UNSET:
            field_dict["rules"] = rules
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        path = d.pop("path")

        def _parse_rules(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        rules = _parse_rules(d.pop("rules", UNSET))

        org_id = d.pop("org_id", UNSET)

        scan_directory_request = cls(
            path=path,
            rules=rules,
            org_id=org_id,
        )

        scan_directory_request.additional_properties = d
        return scan_directory_request

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
