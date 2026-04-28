from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SnapshotRequest")


@_attrs_define
class SnapshotRequest:
    """
    Attributes:
        repo_ref (str):
        org_id (str | Unset):  Default: 'default'.
        scan_id (str | Unset):  Default: ''.
    """

    repo_ref: str
    org_id: str | Unset = "default"
    scan_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo_ref = self.repo_ref

        org_id = self.org_id

        scan_id = self.scan_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_ref": repo_ref,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if scan_id is not UNSET:
            field_dict["scan_id"] = scan_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo_ref = d.pop("repo_ref")

        org_id = d.pop("org_id", UNSET)

        scan_id = d.pop("scan_id", UNSET)

        snapshot_request = cls(
            repo_ref=repo_ref,
            org_id=org_id,
            scan_id=scan_id,
        )

        snapshot_request.additional_properties = d
        return snapshot_request

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
