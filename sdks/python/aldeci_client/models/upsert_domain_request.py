from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="UpsertDomainRequest")


@_attrs_define
class UpsertDomainRequest:
    """
    Attributes:
        domain_name (str): Domain identifier e.g. 'Vulnerability Management'
        domain_category (str): vulnerability | compliance | identity | network | endpoint | cloud | data | physical
        weight (float): Domain weight (0-1), clamped automatically
        score (float): Current raw score
        max_score (float): Maximum possible score
    """

    domain_name: str
    domain_category: str
    weight: float
    score: float
    max_score: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain_name = self.domain_name

        domain_category = self.domain_category

        weight = self.weight

        score = self.score

        max_score = self.max_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain_name": domain_name,
                "domain_category": domain_category,
                "weight": weight,
                "score": score,
                "max_score": max_score,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain_name = d.pop("domain_name")

        domain_category = d.pop("domain_category")

        weight = d.pop("weight")

        score = d.pop("score")

        max_score = d.pop("max_score")

        upsert_domain_request = cls(
            domain_name=domain_name,
            domain_category=domain_category,
            weight=weight,
            score=score,
            max_score=max_score,
        )

        upsert_domain_request.additional_properties = d
        return upsert_domain_request

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
