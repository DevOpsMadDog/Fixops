from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DomainScoreUpdate")


@_attrs_define
class DomainScoreUpdate:
    """
    Attributes:
        score (float):
        evidence (str | Unset):  Default: ''.
        gaps (str | Unset):  Default: ''.
        recommendations (str | Unset):  Default: ''.
    """

    score: float
    evidence: str | Unset = ""
    gaps: str | Unset = ""
    recommendations: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        score = self.score

        evidence = self.evidence

        gaps = self.gaps

        recommendations = self.recommendations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "score": score,
            }
        )
        if evidence is not UNSET:
            field_dict["evidence"] = evidence
        if gaps is not UNSET:
            field_dict["gaps"] = gaps
        if recommendations is not UNSET:
            field_dict["recommendations"] = recommendations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        score = d.pop("score")

        evidence = d.pop("evidence", UNSET)

        gaps = d.pop("gaps", UNSET)

        recommendations = d.pop("recommendations", UNSET)

        domain_score_update = cls(
            score=score,
            evidence=evidence,
            gaps=gaps,
            recommendations=recommendations,
        )

        domain_score_update.additional_properties = d
        return domain_score_update

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
