from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.query_response_evidence_item import QueryResponseEvidenceItem


T = TypeVar("T", bound="QueryResponse")


@_attrs_define
class QueryResponse:
    """Query result.

    Attributes:
        answer (str):
        evidence (list[QueryResponseEvidenceItem]):
        confidence (float):
        sources (list[int]):
        query_time_ms (float):
    """

    answer: str
    evidence: list[QueryResponseEvidenceItem]
    confidence: float
    sources: list[int]
    query_time_ms: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        answer = self.answer

        evidence = []
        for evidence_item_data in self.evidence:
            evidence_item = evidence_item_data.to_dict()
            evidence.append(evidence_item)

        confidence = self.confidence

        sources = self.sources

        query_time_ms = self.query_time_ms

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "answer": answer,
                "evidence": evidence,
                "confidence": confidence,
                "sources": sources,
                "query_time_ms": query_time_ms,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.query_response_evidence_item import QueryResponseEvidenceItem

        d = dict(src_dict)
        answer = d.pop("answer")

        evidence = []
        _evidence = d.pop("evidence")
        for evidence_item_data in _evidence:
            evidence_item = QueryResponseEvidenceItem.from_dict(evidence_item_data)

            evidence.append(evidence_item)

        confidence = d.pop("confidence")

        sources = cast(list[int], d.pop("sources"))

        query_time_ms = d.pop("query_time_ms")

        query_response = cls(
            answer=answer,
            evidence=evidence,
            confidence=confidence,
            sources=sources,
            query_time_ms=query_time_ms,
        )

        query_response.additional_properties = d
        return query_response

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
