from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.finding_mapping_response import FindingMappingResponse
    from ..models.kill_chain_coverage_response import KillChainCoverageResponse
    from ..models.map_findings_response_technique_frequency import MapFindingsResponseTechniqueFrequency


T = TypeVar("T", bound="MapFindingsResponse")


@_attrs_define
class MapFindingsResponse:
    """
    Attributes:
        session_id (str):
        mapped_at (str):
        total_findings (int):
        total_techniques (int):
        total_tactics_covered (int):
        coverage_percentage (float):
        all_techniques (list[str]):
        technique_frequency (MapFindingsResponseTechniqueFrequency):
        kill_chain_coverage (list[KillChainCoverageResponse]):
        finding_results (list[FindingMappingResponse]):
    """

    session_id: str
    mapped_at: str
    total_findings: int
    total_techniques: int
    total_tactics_covered: int
    coverage_percentage: float
    all_techniques: list[str]
    technique_frequency: MapFindingsResponseTechniqueFrequency
    kill_chain_coverage: list[KillChainCoverageResponse]
    finding_results: list[FindingMappingResponse]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        session_id = self.session_id

        mapped_at = self.mapped_at

        total_findings = self.total_findings

        total_techniques = self.total_techniques

        total_tactics_covered = self.total_tactics_covered

        coverage_percentage = self.coverage_percentage

        all_techniques = self.all_techniques

        technique_frequency = self.technique_frequency.to_dict()

        kill_chain_coverage = []
        for kill_chain_coverage_item_data in self.kill_chain_coverage:
            kill_chain_coverage_item = kill_chain_coverage_item_data.to_dict()
            kill_chain_coverage.append(kill_chain_coverage_item)

        finding_results = []
        for finding_results_item_data in self.finding_results:
            finding_results_item = finding_results_item_data.to_dict()
            finding_results.append(finding_results_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "session_id": session_id,
                "mapped_at": mapped_at,
                "total_findings": total_findings,
                "total_techniques": total_techniques,
                "total_tactics_covered": total_tactics_covered,
                "coverage_percentage": coverage_percentage,
                "all_techniques": all_techniques,
                "technique_frequency": technique_frequency,
                "kill_chain_coverage": kill_chain_coverage,
                "finding_results": finding_results,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.finding_mapping_response import FindingMappingResponse
        from ..models.kill_chain_coverage_response import KillChainCoverageResponse
        from ..models.map_findings_response_technique_frequency import MapFindingsResponseTechniqueFrequency

        d = dict(src_dict)
        session_id = d.pop("session_id")

        mapped_at = d.pop("mapped_at")

        total_findings = d.pop("total_findings")

        total_techniques = d.pop("total_techniques")

        total_tactics_covered = d.pop("total_tactics_covered")

        coverage_percentage = d.pop("coverage_percentage")

        all_techniques = cast(list[str], d.pop("all_techniques"))

        technique_frequency = MapFindingsResponseTechniqueFrequency.from_dict(d.pop("technique_frequency"))

        kill_chain_coverage = []
        _kill_chain_coverage = d.pop("kill_chain_coverage")
        for kill_chain_coverage_item_data in _kill_chain_coverage:
            kill_chain_coverage_item = KillChainCoverageResponse.from_dict(kill_chain_coverage_item_data)

            kill_chain_coverage.append(kill_chain_coverage_item)

        finding_results = []
        _finding_results = d.pop("finding_results")
        for finding_results_item_data in _finding_results:
            finding_results_item = FindingMappingResponse.from_dict(finding_results_item_data)

            finding_results.append(finding_results_item)

        map_findings_response = cls(
            session_id=session_id,
            mapped_at=mapped_at,
            total_findings=total_findings,
            total_techniques=total_techniques,
            total_tactics_covered=total_tactics_covered,
            coverage_percentage=coverage_percentage,
            all_techniques=all_techniques,
            technique_frequency=technique_frequency,
            kill_chain_coverage=kill_chain_coverage,
            finding_results=finding_results,
        )

        map_findings_response.additional_properties = d
        return map_findings_response

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
