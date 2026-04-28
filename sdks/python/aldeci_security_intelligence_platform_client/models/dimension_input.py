from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DimensionInput")


@_attrs_define
class DimensionInput:
    """
    Attributes:
        dimension (str): One of: vulnerability_hygiene, patch_compliance, security_training, access_control,
            incident_response, threat_awareness, code_security, configuration_hardening
        score (float):
        weight (float | Unset):  Default: 0.125.
        evidence (str | Unset):  Default: ''.
    """

    dimension: str
    score: float
    weight: float | Unset = 0.125
    evidence: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dimension = self.dimension

        score = self.score

        weight = self.weight

        evidence = self.evidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "dimension": dimension,
                "score": score,
            }
        )
        if weight is not UNSET:
            field_dict["weight"] = weight
        if evidence is not UNSET:
            field_dict["evidence"] = evidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        dimension = d.pop("dimension")

        score = d.pop("score")

        weight = d.pop("weight", UNSET)

        evidence = d.pop("evidence", UNSET)

        dimension_input = cls(
            dimension=dimension,
            score=score,
            weight=weight,
            evidence=evidence,
        )

        dimension_input.additional_properties = d
        return dimension_input

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
