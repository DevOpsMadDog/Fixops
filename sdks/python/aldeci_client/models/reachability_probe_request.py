from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReachabilityProbeRequest")


@_attrs_define
class ReachabilityProbeRequest:
    """Request model for reachability probing.

    Attributes:
        targets (list[str]): Target URLs or host:port to probe
        cve_id (str | Unset): CVE being checked for reachability Default: ''.
        asset_ids (list[str] | Unset): Asset IDs for correlation
    """

    targets: list[str]
    cve_id: str | Unset = ""
    asset_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        targets = self.targets

        cve_id = self.cve_id

        asset_ids: list[str] | Unset = UNSET
        if not isinstance(self.asset_ids, Unset):
            asset_ids = self.asset_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "targets": targets,
            }
        )
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if asset_ids is not UNSET:
            field_dict["asset_ids"] = asset_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        targets = cast(list[str], d.pop("targets"))

        cve_id = d.pop("cve_id", UNSET)

        asset_ids = cast(list[str], d.pop("asset_ids", UNSET))

        reachability_probe_request = cls(
            targets=targets,
            cve_id=cve_id,
            asset_ids=asset_ids,
        )

        reachability_probe_request.additional_properties = d
        return reachability_probe_request

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
