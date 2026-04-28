from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CSPMSnapshotScanRequest")


@_attrs_define
class CSPMSnapshotScanRequest:
    """
    Attributes:
        cloud (str): aws|azure|gcp|kubernetes
        account_id (str): Account / subscription / project id
        snapshot_id (None | str | Unset): Existing snapshot to scan
        regions (list[str] | Unset):
    """

    cloud: str
    account_id: str
    snapshot_id: None | str | Unset = UNSET
    regions: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cloud = self.cloud

        account_id = self.account_id

        snapshot_id: None | str | Unset
        if isinstance(self.snapshot_id, Unset):
            snapshot_id = UNSET
        else:
            snapshot_id = self.snapshot_id

        regions: list[str] | Unset = UNSET
        if not isinstance(self.regions, Unset):
            regions = self.regions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cloud": cloud,
                "account_id": account_id,
            }
        )
        if snapshot_id is not UNSET:
            field_dict["snapshot_id"] = snapshot_id
        if regions is not UNSET:
            field_dict["regions"] = regions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cloud = d.pop("cloud")

        account_id = d.pop("account_id")

        def _parse_snapshot_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        snapshot_id = _parse_snapshot_id(d.pop("snapshot_id", UNSET))

        regions = cast(list[str], d.pop("regions", UNSET))

        cspm_snapshot_scan_request = cls(
            cloud=cloud,
            account_id=account_id,
            snapshot_id=snapshot_id,
            regions=regions,
        )

        cspm_snapshot_scan_request.additional_properties = d
        return cspm_snapshot_scan_request

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
