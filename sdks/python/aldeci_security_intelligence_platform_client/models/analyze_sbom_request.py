from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.analyze_sbom_request_sbom import AnalyzeSBOMRequestSbom


T = TypeVar("T", bound="AnalyzeSBOMRequest")


@_attrs_define
class AnalyzeSBOMRequest:
    """
    Attributes:
        sbom (AnalyzeSBOMRequestSbom): CycloneDX or SPDX SBOM document
        typosquat_threshold (int | Unset):  Default: 2.
        min_age_days (int | Unset):  Default: 30.
        min_downloads (int | Unset):  Default: 100.
    """

    sbom: AnalyzeSBOMRequestSbom
    typosquat_threshold: int | Unset = 2
    min_age_days: int | Unset = 30
    min_downloads: int | Unset = 100
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        sbom = self.sbom.to_dict()

        typosquat_threshold = self.typosquat_threshold

        min_age_days = self.min_age_days

        min_downloads = self.min_downloads

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "sbom": sbom,
            }
        )
        if typosquat_threshold is not UNSET:
            field_dict["typosquat_threshold"] = typosquat_threshold
        if min_age_days is not UNSET:
            field_dict["min_age_days"] = min_age_days
        if min_downloads is not UNSET:
            field_dict["min_downloads"] = min_downloads

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.analyze_sbom_request_sbom import AnalyzeSBOMRequestSbom

        d = dict(src_dict)
        sbom = AnalyzeSBOMRequestSbom.from_dict(d.pop("sbom"))

        typosquat_threshold = d.pop("typosquat_threshold", UNSET)

        min_age_days = d.pop("min_age_days", UNSET)

        min_downloads = d.pop("min_downloads", UNSET)

        analyze_sbom_request = cls(
            sbom=sbom,
            typosquat_threshold=typosquat_threshold,
            min_age_days=min_age_days,
            min_downloads=min_downloads,
        )

        analyze_sbom_request.additional_properties = d
        return analyze_sbom_request

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
