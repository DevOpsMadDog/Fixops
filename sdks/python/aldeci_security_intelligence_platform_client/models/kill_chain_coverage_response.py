from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="KillChainCoverageResponse")


@_attrs_define
class KillChainCoverageResponse:
    """
    Attributes:
        tactic_id (str):
        tactic_name (str):
        covered (bool):
        technique_count (int):
        techniques (list[str]):
        highest_confidence (float):
    """

    tactic_id: str
    tactic_name: str
    covered: bool
    technique_count: int
    techniques: list[str]
    highest_confidence: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tactic_id = self.tactic_id

        tactic_name = self.tactic_name

        covered = self.covered

        technique_count = self.technique_count

        techniques = self.techniques

        highest_confidence = self.highest_confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
                "covered": covered,
                "technique_count": technique_count,
                "techniques": techniques,
                "highest_confidence": highest_confidence,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tactic_id = d.pop("tactic_id")

        tactic_name = d.pop("tactic_name")

        covered = d.pop("covered")

        technique_count = d.pop("technique_count")

        techniques = cast(list[str], d.pop("techniques"))

        highest_confidence = d.pop("highest_confidence")

        kill_chain_coverage_response = cls(
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            covered=covered,
            technique_count=technique_count,
            techniques=techniques,
            highest_confidence=highest_confidence,
        )

        kill_chain_coverage_response.additional_properties = d
        return kill_chain_coverage_response

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
