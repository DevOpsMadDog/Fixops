from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="TechniqueMappingResponse")


@_attrs_define
class TechniqueMappingResponse:
    """
    Attributes:
        technique_id (str):
        technique_name (str):
        tactic_ids (list[str]):
        tactic_names (list[str]):
        confidence (float):
        source (str):
        source_ref (str):
        rationale (str):
        technique_url (str):
    """

    technique_id: str
    technique_name: str
    tactic_ids: list[str]
    tactic_names: list[str]
    confidence: float
    source: str
    source_ref: str
    rationale: str
    technique_url: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        technique_id = self.technique_id

        technique_name = self.technique_name

        tactic_ids = self.tactic_ids

        tactic_names = self.tactic_names

        confidence = self.confidence

        source = self.source

        source_ref = self.source_ref

        rationale = self.rationale

        technique_url = self.technique_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic_ids": tactic_ids,
                "tactic_names": tactic_names,
                "confidence": confidence,
                "source": source,
                "source_ref": source_ref,
                "rationale": rationale,
                "technique_url": technique_url,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        technique_id = d.pop("technique_id")

        technique_name = d.pop("technique_name")

        tactic_ids = cast(list[str], d.pop("tactic_ids"))

        tactic_names = cast(list[str], d.pop("tactic_names"))

        confidence = d.pop("confidence")

        source = d.pop("source")

        source_ref = d.pop("source_ref")

        rationale = d.pop("rationale")

        technique_url = d.pop("technique_url")

        technique_mapping_response = cls(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic_ids=tactic_ids,
            tactic_names=tactic_names,
            confidence=confidence,
            source=source,
            source_ref=source_ref,
            rationale=rationale,
            technique_url=technique_url,
        )

        technique_mapping_response.additional_properties = d
        return technique_mapping_response

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
