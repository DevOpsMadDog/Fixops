from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.decision_outcome import DecisionOutcome
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.decision_create_llm_votes import DecisionCreateLlmVotes


T = TypeVar("T", bound="DecisionCreate")


@_attrs_define
class DecisionCreate:
    """Request model for creating a decision.

    Attributes:
        finding_id (str):
        outcome (DecisionOutcome): Decision outcome.
        confidence (float):
        reasoning (str):
        llm_votes (DecisionCreateLlmVotes | Unset):
        policy_matched (None | str | Unset):
    """

    finding_id: str
    outcome: DecisionOutcome
    confidence: float
    reasoning: str
    llm_votes: DecisionCreateLlmVotes | Unset = UNSET
    policy_matched: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        outcome = self.outcome.value

        confidence = self.confidence

        reasoning = self.reasoning

        llm_votes: dict[str, Any] | Unset = UNSET
        if not isinstance(self.llm_votes, Unset):
            llm_votes = self.llm_votes.to_dict()

        policy_matched: None | str | Unset
        if isinstance(self.policy_matched, Unset):
            policy_matched = UNSET
        else:
            policy_matched = self.policy_matched

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "outcome": outcome,
                "confidence": confidence,
                "reasoning": reasoning,
            }
        )
        if llm_votes is not UNSET:
            field_dict["llm_votes"] = llm_votes
        if policy_matched is not UNSET:
            field_dict["policy_matched"] = policy_matched

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.decision_create_llm_votes import DecisionCreateLlmVotes

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        outcome = DecisionOutcome(d.pop("outcome"))

        confidence = d.pop("confidence")

        reasoning = d.pop("reasoning")

        _llm_votes = d.pop("llm_votes", UNSET)
        llm_votes: DecisionCreateLlmVotes | Unset
        if isinstance(_llm_votes, Unset):
            llm_votes = UNSET
        else:
            llm_votes = DecisionCreateLlmVotes.from_dict(_llm_votes)

        def _parse_policy_matched(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        policy_matched = _parse_policy_matched(d.pop("policy_matched", UNSET))

        decision_create = cls(
            finding_id=finding_id,
            outcome=outcome,
            confidence=confidence,
            reasoning=reasoning,
            llm_votes=llm_votes,
            policy_matched=policy_matched,
        )

        decision_create.additional_properties = d
        return decision_create

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
