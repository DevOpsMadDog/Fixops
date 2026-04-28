from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.coverage_report_response_cores import CoverageReportResponseCores


T = TypeVar("T", bound="CoverageReportResponse")


@_attrs_define
class CoverageReportResponse:
    """Overall coverage report across all Knowledge Cores.

    Attributes:
        cores (CoverageReportResponseCores):
        total_coverage_pct (float):
        total_entities (int):
        connected_entities (int):
        orphaned_count (int):
        last_checked (str):
    """

    cores: CoverageReportResponseCores
    total_coverage_pct: float
    total_entities: int
    connected_entities: int
    orphaned_count: int
    last_checked: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cores = self.cores.to_dict()

        total_coverage_pct = self.total_coverage_pct

        total_entities = self.total_entities

        connected_entities = self.connected_entities

        orphaned_count = self.orphaned_count

        last_checked = self.last_checked

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cores": cores,
                "total_coverage_pct": total_coverage_pct,
                "total_entities": total_entities,
                "connected_entities": connected_entities,
                "orphaned_count": orphaned_count,
                "last_checked": last_checked,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.coverage_report_response_cores import CoverageReportResponseCores

        d = dict(src_dict)
        cores = CoverageReportResponseCores.from_dict(d.pop("cores"))

        total_coverage_pct = d.pop("total_coverage_pct")

        total_entities = d.pop("total_entities")

        connected_entities = d.pop("connected_entities")

        orphaned_count = d.pop("orphaned_count")

        last_checked = d.pop("last_checked")

        coverage_report_response = cls(
            cores=cores,
            total_coverage_pct=total_coverage_pct,
            total_entities=total_entities,
            connected_entities=connected_entities,
            orphaned_count=orphaned_count,
            last_checked=last_checked,
        )

        coverage_report_response.additional_properties = d
        return coverage_report_response

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
