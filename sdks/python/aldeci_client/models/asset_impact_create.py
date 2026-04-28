from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssetImpactCreate")


@_attrs_define
class AssetImpactCreate:
    """
    Attributes:
        cve_id (str):
        asset_id (str):
        asset_name (str | Unset):  Default: ''.
        asset_criticality (str | Unset):  Default: 'medium'.
        exposure (str | Unset):  Default: 'unknown'.
        remediation_priority (int | Unset):  Default: 3.
    """

    cve_id: str
    asset_id: str
    asset_name: str | Unset = ""
    asset_criticality: str | Unset = "medium"
    exposure: str | Unset = "unknown"
    remediation_priority: int | Unset = 3
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        asset_id = self.asset_id

        asset_name = self.asset_name

        asset_criticality = self.asset_criticality

        exposure = self.exposure

        remediation_priority = self.remediation_priority

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "asset_id": asset_id,
            }
        )
        if asset_name is not UNSET:
            field_dict["asset_name"] = asset_name
        if asset_criticality is not UNSET:
            field_dict["asset_criticality"] = asset_criticality
        if exposure is not UNSET:
            field_dict["exposure"] = exposure
        if remediation_priority is not UNSET:
            field_dict["remediation_priority"] = remediation_priority

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        asset_id = d.pop("asset_id")

        asset_name = d.pop("asset_name", UNSET)

        asset_criticality = d.pop("asset_criticality", UNSET)

        exposure = d.pop("exposure", UNSET)

        remediation_priority = d.pop("remediation_priority", UNSET)

        asset_impact_create = cls(
            cve_id=cve_id,
            asset_id=asset_id,
            asset_name=asset_name,
            asset_criticality=asset_criticality,
            exposure=exposure,
            remediation_priority=remediation_priority,
        )

        asset_impact_create.additional_properties = d
        return asset_impact_create

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
