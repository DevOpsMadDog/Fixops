from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ASMSurfaceScore")


@_attrs_define
class ASMSurfaceScore:
    """Overall attack surface score with breakdown.

    Attributes:
        org_id (str):
        overall_score (float):
        exposure_score (float):
        vulnerability_score (float):
        configuration_score (float):
        certificate_score (float):
        shadow_it_score (float):
        total_assets (int):
        internet_facing_count (int):
        critical_assets (int):
        shadow_it_count (int):
        unpatched_assets (int):
        expiring_certs (int):
        computed_at (str | Unset):
    """

    org_id: str
    overall_score: float
    exposure_score: float
    vulnerability_score: float
    configuration_score: float
    certificate_score: float
    shadow_it_score: float
    total_assets: int
    internet_facing_count: int
    critical_assets: int
    shadow_it_count: int
    unpatched_assets: int
    expiring_certs: int
    computed_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        overall_score = self.overall_score

        exposure_score = self.exposure_score

        vulnerability_score = self.vulnerability_score

        configuration_score = self.configuration_score

        certificate_score = self.certificate_score

        shadow_it_score = self.shadow_it_score

        total_assets = self.total_assets

        internet_facing_count = self.internet_facing_count

        critical_assets = self.critical_assets

        shadow_it_count = self.shadow_it_count

        unpatched_assets = self.unpatched_assets

        expiring_certs = self.expiring_certs

        computed_at = self.computed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "overall_score": overall_score,
                "exposure_score": exposure_score,
                "vulnerability_score": vulnerability_score,
                "configuration_score": configuration_score,
                "certificate_score": certificate_score,
                "shadow_it_score": shadow_it_score,
                "total_assets": total_assets,
                "internet_facing_count": internet_facing_count,
                "critical_assets": critical_assets,
                "shadow_it_count": shadow_it_count,
                "unpatched_assets": unpatched_assets,
                "expiring_certs": expiring_certs,
            }
        )
        if computed_at is not UNSET:
            field_dict["computed_at"] = computed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        overall_score = d.pop("overall_score")

        exposure_score = d.pop("exposure_score")

        vulnerability_score = d.pop("vulnerability_score")

        configuration_score = d.pop("configuration_score")

        certificate_score = d.pop("certificate_score")

        shadow_it_score = d.pop("shadow_it_score")

        total_assets = d.pop("total_assets")

        internet_facing_count = d.pop("internet_facing_count")

        critical_assets = d.pop("critical_assets")

        shadow_it_count = d.pop("shadow_it_count")

        unpatched_assets = d.pop("unpatched_assets")

        expiring_certs = d.pop("expiring_certs")

        computed_at = d.pop("computed_at", UNSET)

        asm_surface_score = cls(
            org_id=org_id,
            overall_score=overall_score,
            exposure_score=exposure_score,
            vulnerability_score=vulnerability_score,
            configuration_score=configuration_score,
            certificate_score=certificate_score,
            shadow_it_score=shadow_it_score,
            total_assets=total_assets,
            internet_facing_count=internet_facing_count,
            critical_assets=critical_assets,
            shadow_it_count=shadow_it_count,
            unpatched_assets=unpatched_assets,
            expiring_certs=expiring_certs,
            computed_at=computed_at,
        )

        asm_surface_score.additional_properties = d
        return asm_surface_score

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
