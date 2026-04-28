from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ZeroTrustDimension")


@_attrs_define
class ZeroTrustDimension:
    """
    Attributes:
        name (str):
        score (float):
        weight (float):
        findings (list[str] | Unset):
    """

    name: str
    score: float
    weight: float
    findings: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        score = self.score

        weight = self.weight

        findings: list[str] | Unset = UNSET
        if not isinstance(self.findings, Unset):
            findings = self.findings

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "score": score,
                "weight": weight,
            }
        )
        if findings is not UNSET:
            field_dict["findings"] = findings

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        score = d.pop("score")

        weight = d.pop("weight")

        findings = cast(list[str], d.pop("findings", UNSET))

        zero_trust_dimension = cls(
            name=name,
            score=score,
            weight=weight,
            findings=findings,
        )

        zero_trust_dimension.additional_properties = d
        return zero_trust_dimension

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
