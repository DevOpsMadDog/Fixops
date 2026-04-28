from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichAlertRequest")


@_attrs_define
class EnrichAlertRequest:
    """
    Attributes:
        source_name (str): Enrichment source name
        result_type (str): ioc_match | geolocation | asset_info | vuln_info | reputation | error
        result_data (str | Unset): Enrichment result payload Default: ''.
        ioc_matches (int | Unset): Number of IOC matches found Default: 0.
        confidence_score (float | Unset): Confidence score 0.0-1.0 Default: 0.0.
    """

    source_name: str
    result_type: str
    result_data: str | Unset = ""
    ioc_matches: int | Unset = 0
    confidence_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_name = self.source_name

        result_type = self.result_type

        result_data = self.result_data

        ioc_matches = self.ioc_matches

        confidence_score = self.confidence_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_name": source_name,
                "result_type": result_type,
            }
        )
        if result_data is not UNSET:
            field_dict["result_data"] = result_data
        if ioc_matches is not UNSET:
            field_dict["ioc_matches"] = ioc_matches
        if confidence_score is not UNSET:
            field_dict["confidence_score"] = confidence_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_name = d.pop("source_name")

        result_type = d.pop("result_type")

        result_data = d.pop("result_data", UNSET)

        ioc_matches = d.pop("ioc_matches", UNSET)

        confidence_score = d.pop("confidence_score", UNSET)

        enrich_alert_request = cls(
            source_name=source_name,
            result_type=result_type,
            result_data=result_data,
            ioc_matches=ioc_matches,
            confidence_score=confidence_score,
        )

        enrich_alert_request.additional_properties = d
        return enrich_alert_request

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
