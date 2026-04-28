from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanWithConfigRequest")


@_attrs_define
class ScanWithConfigRequest:
    """Request body for scanning with a custom semgrep config.

    Attributes:
        path (str): Filesystem path to scan
        config (str): Semgrep config — registry ID, local YAML file, or URL
        org_id (str | Unset): Organisation identifier Default: 'default'.
    """

    path: str
    config: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        path = self.path

        config = self.config

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "path": path,
                "config": config,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        path = d.pop("path")

        config = d.pop("config")

        org_id = d.pop("org_id", UNSET)

        scan_with_config_request = cls(
            path=path,
            config=config,
            org_id=org_id,
        )

        scan_with_config_request.additional_properties = d
        return scan_with_config_request

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
