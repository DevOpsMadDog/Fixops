from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.decision_response_consensus_details import DecisionResponseConsensusDetails
    from ..models.decision_response_validation_results import DecisionResponseValidationResults


T = TypeVar("T", bound="DecisionResponse")


@_attrs_define
class DecisionResponse:
    """
    Attributes:
        decision (str):
        confidence_score (float):
        evidence_id (str):
        reasoning (str):
        processing_time_us (float):
        consensus_details (DecisionResponseConsensusDetails):
        validation_results (DecisionResponseValidationResults):
    """

    decision: str
    confidence_score: float
    evidence_id: str
    reasoning: str
    processing_time_us: float
    consensus_details: DecisionResponseConsensusDetails
    validation_results: DecisionResponseValidationResults
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        decision = self.decision

        confidence_score = self.confidence_score

        evidence_id = self.evidence_id

        reasoning = self.reasoning

        processing_time_us = self.processing_time_us

        consensus_details = self.consensus_details.to_dict()

        validation_results = self.validation_results.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "decision": decision,
                "confidence_score": confidence_score,
                "evidence_id": evidence_id,
                "reasoning": reasoning,
                "processing_time_us": processing_time_us,
                "consensus_details": consensus_details,
                "validation_results": validation_results,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.decision_response_consensus_details import DecisionResponseConsensusDetails
        from ..models.decision_response_validation_results import DecisionResponseValidationResults

        d = dict(src_dict)
        decision = d.pop("decision")

        confidence_score = d.pop("confidence_score")

        evidence_id = d.pop("evidence_id")

        reasoning = d.pop("reasoning")

        processing_time_us = d.pop("processing_time_us")

        consensus_details = DecisionResponseConsensusDetails.from_dict(d.pop("consensus_details"))

        validation_results = DecisionResponseValidationResults.from_dict(d.pop("validation_results"))

        decision_response = cls(
            decision=decision,
            confidence_score=confidence_score,
            evidence_id=evidence_id,
            reasoning=reasoning,
            processing_time_us=processing_time_us,
            consensus_details=consensus_details,
            validation_results=validation_results,
        )

        decision_response.additional_properties = d
        return decision_response

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
