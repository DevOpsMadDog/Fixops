from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="EvidenceCoverage")


@_attrs_define
class EvidenceCoverage:
    """Coverage report: which controls have fresh evidence.

    Attributes:
        org_id (str):
        framework (str):
        total_controls (int):
        covered_controls (int):
        coverage_pct (float):
        fresh_controls (list[str]):
        stale_controls (list[str]):
        missing_controls (list[str]):
        generated_at (datetime.datetime | Unset):
    """

    org_id: str
    framework: str
    total_controls: int
    covered_controls: int
    coverage_pct: float
    fresh_controls: list[str]
    stale_controls: list[str]
    missing_controls: list[str]
    generated_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        framework = self.framework

        total_controls = self.total_controls

        covered_controls = self.covered_controls

        coverage_pct = self.coverage_pct

        fresh_controls = self.fresh_controls

        stale_controls = self.stale_controls

        missing_controls = self.missing_controls

        generated_at: str | Unset = UNSET
        if not isinstance(self.generated_at, Unset):
            generated_at = self.generated_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "framework": framework,
                "total_controls": total_controls,
                "covered_controls": covered_controls,
                "coverage_pct": coverage_pct,
                "fresh_controls": fresh_controls,
                "stale_controls": stale_controls,
                "missing_controls": missing_controls,
            }
        )
        if generated_at is not UNSET:
            field_dict["generated_at"] = generated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        framework = d.pop("framework")

        total_controls = d.pop("total_controls")

        covered_controls = d.pop("covered_controls")

        coverage_pct = d.pop("coverage_pct")

        fresh_controls = cast(list[str], d.pop("fresh_controls"))

        stale_controls = cast(list[str], d.pop("stale_controls"))

        missing_controls = cast(list[str], d.pop("missing_controls"))

        _generated_at = d.pop("generated_at", UNSET)
        generated_at: datetime.datetime | Unset
        if isinstance(_generated_at, Unset):
            generated_at = UNSET
        else:
            generated_at = isoparse(_generated_at)

        evidence_coverage = cls(
            org_id=org_id,
            framework=framework,
            total_controls=total_controls,
            covered_controls=covered_controls,
            coverage_pct=coverage_pct,
            fresh_controls=fresh_controls,
            stale_controls=stale_controls,
            missing_controls=missing_controls,
            generated_at=generated_at,
        )

        evidence_coverage.additional_properties = d
        return evidence_coverage

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
