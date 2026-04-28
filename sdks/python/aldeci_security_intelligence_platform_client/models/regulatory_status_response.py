from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RegulatoryStatusResponse")


@_attrs_define
class RegulatoryStatusResponse:
    """Regulatory compliance status and exposure.

    Attributes:
        regulation (str):
        compliance_pct (float):
        max_fine_usd (float):
        estimated_exposure_usd (float):
        gap_count (int):
        remediation_eta_days (int):
        color (str):
        key_gaps (list[str]):
    """

    regulation: str
    compliance_pct: float
    max_fine_usd: float
    estimated_exposure_usd: float
    gap_count: int
    remediation_eta_days: int
    color: str
    key_gaps: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        regulation = self.regulation

        compliance_pct = self.compliance_pct

        max_fine_usd = self.max_fine_usd

        estimated_exposure_usd = self.estimated_exposure_usd

        gap_count = self.gap_count

        remediation_eta_days = self.remediation_eta_days

        color = self.color

        key_gaps = self.key_gaps

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "regulation": regulation,
                "compliance_pct": compliance_pct,
                "max_fine_usd": max_fine_usd,
                "estimated_exposure_usd": estimated_exposure_usd,
                "gap_count": gap_count,
                "remediation_eta_days": remediation_eta_days,
                "color": color,
                "key_gaps": key_gaps,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        regulation = d.pop("regulation")

        compliance_pct = d.pop("compliance_pct")

        max_fine_usd = d.pop("max_fine_usd")

        estimated_exposure_usd = d.pop("estimated_exposure_usd")

        gap_count = d.pop("gap_count")

        remediation_eta_days = d.pop("remediation_eta_days")

        color = d.pop("color")

        key_gaps = cast(list[str], d.pop("key_gaps"))

        regulatory_status_response = cls(
            regulation=regulation,
            compliance_pct=compliance_pct,
            max_fine_usd=max_fine_usd,
            estimated_exposure_usd=estimated_exposure_usd,
            gap_count=gap_count,
            remediation_eta_days=remediation_eta_days,
            color=color,
            key_gaps=key_gaps,
        )

        regulatory_status_response.additional_properties = d
        return regulatory_status_response

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
