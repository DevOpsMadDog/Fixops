from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MgrScanRequest")


@_attrs_define
class MgrScanRequest:
    """
    Attributes:
        target_path (str): Absolute path to repo or file to scan
        scan_type (str | Unset): filesystem | git_history Default: 'filesystem'.
        include_git_history (bool | Unset): Also scan git commit history Default: False.
    """

    target_path: str
    scan_type: str | Unset = "filesystem"
    include_git_history: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target_path = self.target_path

        scan_type = self.scan_type

        include_git_history = self.include_git_history

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "target_path": target_path,
            }
        )
        if scan_type is not UNSET:
            field_dict["scan_type"] = scan_type
        if include_git_history is not UNSET:
            field_dict["include_git_history"] = include_git_history

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target_path = d.pop("target_path")

        scan_type = d.pop("scan_type", UNSET)

        include_git_history = d.pop("include_git_history", UNSET)

        mgr_scan_request = cls(
            target_path=target_path,
            scan_type=scan_type,
            include_git_history=include_git_history,
        )

        mgr_scan_request.additional_properties = d
        return mgr_scan_request

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
