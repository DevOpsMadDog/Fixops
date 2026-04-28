from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.set_trust_score_request_score_factors import SetTrustScoreRequestScoreFactors


T = TypeVar("T", bound="SetTrustScoreRequest")


@_attrs_define
class SetTrustScoreRequest:
    """
    Attributes:
        entity_id (str):
        trust_score (float):
        entity_type (str | Unset): user | device | service Default: 'user'.
        score_factors (SetTrustScoreRequestScoreFactors | Unset):
    """

    entity_id: str
    trust_score: float
    entity_type: str | Unset = "user"
    score_factors: SetTrustScoreRequestScoreFactors | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_id = self.entity_id

        trust_score = self.trust_score

        entity_type = self.entity_type

        score_factors: dict[str, Any] | Unset = UNSET
        if not isinstance(self.score_factors, Unset):
            score_factors = self.score_factors.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_id": entity_id,
                "trust_score": trust_score,
            }
        )
        if entity_type is not UNSET:
            field_dict["entity_type"] = entity_type
        if score_factors is not UNSET:
            field_dict["score_factors"] = score_factors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.set_trust_score_request_score_factors import SetTrustScoreRequestScoreFactors

        d = dict(src_dict)
        entity_id = d.pop("entity_id")

        trust_score = d.pop("trust_score")

        entity_type = d.pop("entity_type", UNSET)

        _score_factors = d.pop("score_factors", UNSET)
        score_factors: SetTrustScoreRequestScoreFactors | Unset
        if isinstance(_score_factors, Unset):
            score_factors = UNSET
        else:
            score_factors = SetTrustScoreRequestScoreFactors.from_dict(_score_factors)

        set_trust_score_request = cls(
            entity_id=entity_id,
            trust_score=trust_score,
            entity_type=entity_type,
            score_factors=score_factors,
        )

        set_trust_score_request.additional_properties = d
        return set_trust_score_request

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
