from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.kill_chain_coverage_response import KillChainCoverageResponse
    from ..models.kill_chain_response_summary import KillChainResponseSummary


T = TypeVar("T", bound="KillChainResponse")


@_attrs_define
class KillChainResponse:
    """
    Attributes:
        session_id (str):
        mapped_at (str):
        total_findings (int):
        total_tactics_covered (int):
        total_tactics (int):
        coverage_percentage (float):
        kill_chain_coverage (list[KillChainCoverageResponse]):
        summary (KillChainResponseSummary):
    """

    session_id: str
    mapped_at: str
    total_findings: int
    total_tactics_covered: int
    total_tactics: int
    coverage_percentage: float
    kill_chain_coverage: list[KillChainCoverageResponse]
    summary: KillChainResponseSummary
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        session_id = self.session_id

        mapped_at = self.mapped_at

        total_findings = self.total_findings

        total_tactics_covered = self.total_tactics_covered

        total_tactics = self.total_tactics

        coverage_percentage = self.coverage_percentage

        kill_chain_coverage = []
        for kill_chain_coverage_item_data in self.kill_chain_coverage:
            kill_chain_coverage_item = kill_chain_coverage_item_data.to_dict()
            kill_chain_coverage.append(kill_chain_coverage_item)

        summary = self.summary.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "session_id": session_id,
                "mapped_at": mapped_at,
                "total_findings": total_findings,
                "total_tactics_covered": total_tactics_covered,
                "total_tactics": total_tactics,
                "coverage_percentage": coverage_percentage,
                "kill_chain_coverage": kill_chain_coverage,
                "summary": summary,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.kill_chain_coverage_response import KillChainCoverageResponse
        from ..models.kill_chain_response_summary import KillChainResponseSummary

        d = dict(src_dict)
        session_id = d.pop("session_id")

        mapped_at = d.pop("mapped_at")

        total_findings = d.pop("total_findings")

        total_tactics_covered = d.pop("total_tactics_covered")

        total_tactics = d.pop("total_tactics")

        coverage_percentage = d.pop("coverage_percentage")

        kill_chain_coverage = []
        _kill_chain_coverage = d.pop("kill_chain_coverage")
        for kill_chain_coverage_item_data in _kill_chain_coverage:
            kill_chain_coverage_item = KillChainCoverageResponse.from_dict(kill_chain_coverage_item_data)

            kill_chain_coverage.append(kill_chain_coverage_item)

        summary = KillChainResponseSummary.from_dict(d.pop("summary"))

        kill_chain_response = cls(
            session_id=session_id,
            mapped_at=mapped_at,
            total_findings=total_findings,
            total_tactics_covered=total_tactics_covered,
            total_tactics=total_tactics,
            coverage_percentage=coverage_percentage,
            kill_chain_coverage=kill_chain_coverage,
            summary=summary,
        )

        kill_chain_response.additional_properties = d
        return kill_chain_response

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
