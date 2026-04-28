from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessDomainRequest")


@_attrs_define
class AssessDomainRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        current_level (int): Current maturity level (1-5)
        score (float): Assessment score (0-100)
        evidence (str | Unset): Supporting evidence Default: ''.
    """

    org_id: str
    current_level: int
    score: float
    evidence: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        current_level = self.current_level

        score = self.score

        evidence = self.evidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "current_level": current_level,
                "score": score,
            }
        )
        if evidence is not UNSET:
            field_dict["evidence"] = evidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        current_level = d.pop("current_level")

        score = d.pop("score")

        evidence = d.pop("evidence", UNSET)

        assess_domain_request = cls(
            org_id=org_id,
            current_level=current_level,
            score=score,
            evidence=evidence,
        )

        assess_domain_request.additional_properties = d
        return assess_domain_request

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
