from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.technique_mapping_response import TechniqueMappingResponse


T = TypeVar("T", bound="FindingMappingResponse")


@_attrs_define
class FindingMappingResponse:
    """
    Attributes:
        finding_id (str):
        finding_title (str):
        cwe_id (None | str):
        cve_ids (list[str]):
        primary_tactic (None | str):
        risk_score (float):
        techniques (list[TechniqueMappingResponse]):
    """

    finding_id: str
    finding_title: str
    cwe_id: None | str
    cve_ids: list[str]
    primary_tactic: None | str
    risk_score: float
    techniques: list[TechniqueMappingResponse]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        finding_title = self.finding_title

        cwe_id: None | str
        cwe_id = self.cwe_id

        cve_ids = self.cve_ids

        primary_tactic: None | str
        primary_tactic = self.primary_tactic

        risk_score = self.risk_score

        techniques = []
        for techniques_item_data in self.techniques:
            techniques_item = techniques_item_data.to_dict()
            techniques.append(techniques_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "finding_title": finding_title,
                "cwe_id": cwe_id,
                "cve_ids": cve_ids,
                "primary_tactic": primary_tactic,
                "risk_score": risk_score,
                "techniques": techniques,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.technique_mapping_response import TechniqueMappingResponse

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        finding_title = d.pop("finding_title")

        def _parse_cwe_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        cwe_id = _parse_cwe_id(d.pop("cwe_id"))

        cve_ids = cast(list[str], d.pop("cve_ids"))

        def _parse_primary_tactic(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        primary_tactic = _parse_primary_tactic(d.pop("primary_tactic"))

        risk_score = d.pop("risk_score")

        techniques = []
        _techniques = d.pop("techniques")
        for techniques_item_data in _techniques:
            techniques_item = TechniqueMappingResponse.from_dict(techniques_item_data)

            techniques.append(techniques_item)

        finding_mapping_response = cls(
            finding_id=finding_id,
            finding_title=finding_title,
            cwe_id=cwe_id,
            cve_ids=cve_ids,
            primary_tactic=primary_tactic,
            risk_score=risk_score,
            techniques=techniques,
        )

        finding_mapping_response.additional_properties = d
        return finding_mapping_response

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
