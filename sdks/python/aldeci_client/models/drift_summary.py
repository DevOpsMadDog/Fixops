from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.drift_summary_by_provider import DriftSummaryByProvider
    from ..models.drift_summary_by_severity import DriftSummaryBySeverity
    from ..models.drift_summary_top_drifts_item import DriftSummaryTopDriftsItem


T = TypeVar("T", bound="DriftSummary")


@_attrs_define
class DriftSummary:
    """Aggregated drift summary for an organisation.

    Attributes:
        total_resources (int):
        compliant (int):
        drifted (int):
        compliance_rate (float):
        by_severity (DriftSummaryBySeverity):
        by_provider (DriftSummaryByProvider):
        top_drifts (list[DriftSummaryTopDriftsItem]):
    """

    total_resources: int
    compliant: int
    drifted: int
    compliance_rate: float
    by_severity: DriftSummaryBySeverity
    by_provider: DriftSummaryByProvider
    top_drifts: list[DriftSummaryTopDriftsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total_resources = self.total_resources

        compliant = self.compliant

        drifted = self.drifted

        compliance_rate = self.compliance_rate

        by_severity = self.by_severity.to_dict()

        by_provider = self.by_provider.to_dict()

        top_drifts = []
        for top_drifts_item_data in self.top_drifts:
            top_drifts_item = top_drifts_item_data.to_dict()
            top_drifts.append(top_drifts_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total_resources": total_resources,
                "compliant": compliant,
                "drifted": drifted,
                "compliance_rate": compliance_rate,
                "by_severity": by_severity,
                "by_provider": by_provider,
                "top_drifts": top_drifts,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.drift_summary_by_provider import DriftSummaryByProvider
        from ..models.drift_summary_by_severity import DriftSummaryBySeverity
        from ..models.drift_summary_top_drifts_item import DriftSummaryTopDriftsItem

        d = dict(src_dict)
        total_resources = d.pop("total_resources")

        compliant = d.pop("compliant")

        drifted = d.pop("drifted")

        compliance_rate = d.pop("compliance_rate")

        by_severity = DriftSummaryBySeverity.from_dict(d.pop("by_severity"))

        by_provider = DriftSummaryByProvider.from_dict(d.pop("by_provider"))

        top_drifts = []
        _top_drifts = d.pop("top_drifts")
        for top_drifts_item_data in _top_drifts:
            top_drifts_item = DriftSummaryTopDriftsItem.from_dict(top_drifts_item_data)

            top_drifts.append(top_drifts_item)

        drift_summary = cls(
            total_resources=total_resources,
            compliant=compliant,
            drifted=drifted,
            compliance_rate=compliance_rate,
            by_severity=by_severity,
            by_provider=by_provider,
            top_drifts=top_drifts,
        )

        drift_summary.additional_properties = d
        return drift_summary

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
