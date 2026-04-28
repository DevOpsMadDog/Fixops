from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DastScanRequest")


@_attrs_define
class DastScanRequest:
    """Request payload for POST /api/v1/connectors/dast/scan.

    Attributes:
        org_id (str): Tenant ID
        target (str): Target URL (http/https). Example: http://localhost:3001
        scanners (list[str] | Unset): Subset of {'nuclei','zap'} to run.
        mirror_to_bug_bounty (bool | Unset): If true, high/critical findings are forwarded into the bug-bounty workflow.
            Default: True.
        timeout_per_scanner (int | Unset): Per-scanner hard timeout in seconds (30..3600). Default: 600.
    """

    org_id: str
    target: str
    scanners: list[str] | Unset = UNSET
    mirror_to_bug_bounty: bool | Unset = True
    timeout_per_scanner: int | Unset = 600
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        target = self.target

        scanners: list[str] | Unset = UNSET
        if not isinstance(self.scanners, Unset):
            scanners = self.scanners

        mirror_to_bug_bounty = self.mirror_to_bug_bounty

        timeout_per_scanner = self.timeout_per_scanner

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "target": target,
            }
        )
        if scanners is not UNSET:
            field_dict["scanners"] = scanners
        if mirror_to_bug_bounty is not UNSET:
            field_dict["mirror_to_bug_bounty"] = mirror_to_bug_bounty
        if timeout_per_scanner is not UNSET:
            field_dict["timeout_per_scanner"] = timeout_per_scanner

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        target = d.pop("target")

        scanners = cast(list[str], d.pop("scanners", UNSET))

        mirror_to_bug_bounty = d.pop("mirror_to_bug_bounty", UNSET)

        timeout_per_scanner = d.pop("timeout_per_scanner", UNSET)

        dast_scan_request = cls(
            org_id=org_id,
            target=target,
            scanners=scanners,
            mirror_to_bug_bounty=mirror_to_bug_bounty,
            timeout_per_scanner=timeout_per_scanner,
        )

        dast_scan_request.additional_properties = d
        return dast_scan_request

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
