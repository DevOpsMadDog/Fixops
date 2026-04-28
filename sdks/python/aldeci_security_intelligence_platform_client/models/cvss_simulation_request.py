from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CVSSSimulationRequest")


@_attrs_define
class CVSSSimulationRequest:
    """Simplified simulation from CVSS score.

    Attributes:
        cvss_score (float): CVSS score
        asset_value (float | Unset): Asset value ($) Default: 1000000.0.
        has_exploit (bool | Unset):  Default: False.
        is_internet_facing (bool | Unset):  Default: False.
        industry (str | Unset): Industry vertical Default: 'technology'.
        iterations (int | Unset):  Default: 10000.
    """

    cvss_score: float
    asset_value: float | Unset = 1000000.0
    has_exploit: bool | Unset = False
    is_internet_facing: bool | Unset = False
    industry: str | Unset = "technology"
    iterations: int | Unset = 10000
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cvss_score = self.cvss_score

        asset_value = self.asset_value

        has_exploit = self.has_exploit

        is_internet_facing = self.is_internet_facing

        industry = self.industry

        iterations = self.iterations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cvss_score": cvss_score,
            }
        )
        if asset_value is not UNSET:
            field_dict["asset_value"] = asset_value
        if has_exploit is not UNSET:
            field_dict["has_exploit"] = has_exploit
        if is_internet_facing is not UNSET:
            field_dict["is_internet_facing"] = is_internet_facing
        if industry is not UNSET:
            field_dict["industry"] = industry
        if iterations is not UNSET:
            field_dict["iterations"] = iterations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cvss_score = d.pop("cvss_score")

        asset_value = d.pop("asset_value", UNSET)

        has_exploit = d.pop("has_exploit", UNSET)

        is_internet_facing = d.pop("is_internet_facing", UNSET)

        industry = d.pop("industry", UNSET)

        iterations = d.pop("iterations", UNSET)

        cvss_simulation_request = cls(
            cvss_score=cvss_score,
            asset_value=asset_value,
            has_exploit=has_exploit,
            is_internet_facing=is_internet_facing,
            industry=industry,
            iterations=iterations,
        )

        cvss_simulation_request.additional_properties = d
        return cvss_simulation_request

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
