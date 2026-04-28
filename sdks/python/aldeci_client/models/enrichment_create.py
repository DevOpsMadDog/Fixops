from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichmentCreate")


@_attrs_define
class EnrichmentCreate:
    """
    Attributes:
        ioc_value (str):
        ioc_type (str | Unset):  Default: 'ip'.
        sources (list[str] | Unset):
        confidence_score (float | Unset):  Default: 0.0.
        threat_categories (list[str] | Unset):
        is_malicious (bool | Unset):  Default: False.
        first_seen (None | str | Unset):
        last_seen (None | str | Unset):
    """

    ioc_value: str
    ioc_type: str | Unset = "ip"
    sources: list[str] | Unset = UNSET
    confidence_score: float | Unset = 0.0
    threat_categories: list[str] | Unset = UNSET
    is_malicious: bool | Unset = False
    first_seen: None | str | Unset = UNSET
    last_seen: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ioc_value = self.ioc_value

        ioc_type = self.ioc_type

        sources: list[str] | Unset = UNSET
        if not isinstance(self.sources, Unset):
            sources = self.sources

        confidence_score = self.confidence_score

        threat_categories: list[str] | Unset = UNSET
        if not isinstance(self.threat_categories, Unset):
            threat_categories = self.threat_categories

        is_malicious = self.is_malicious

        first_seen: None | str | Unset
        if isinstance(self.first_seen, Unset):
            first_seen = UNSET
        else:
            first_seen = self.first_seen

        last_seen: None | str | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ioc_value": ioc_value,
            }
        )
        if ioc_type is not UNSET:
            field_dict["ioc_type"] = ioc_type
        if sources is not UNSET:
            field_dict["sources"] = sources
        if confidence_score is not UNSET:
            field_dict["confidence_score"] = confidence_score
        if threat_categories is not UNSET:
            field_dict["threat_categories"] = threat_categories
        if is_malicious is not UNSET:
            field_dict["is_malicious"] = is_malicious
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ioc_value = d.pop("ioc_value")

        ioc_type = d.pop("ioc_type", UNSET)

        sources = cast(list[str], d.pop("sources", UNSET))

        confidence_score = d.pop("confidence_score", UNSET)

        threat_categories = cast(list[str], d.pop("threat_categories", UNSET))

        is_malicious = d.pop("is_malicious", UNSET)

        def _parse_first_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_seen = _parse_first_seen(d.pop("first_seen", UNSET))

        def _parse_last_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        enrichment_create = cls(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            sources=sources,
            confidence_score=confidence_score,
            threat_categories=threat_categories,
            is_malicious=is_malicious,
            first_seen=first_seen,
            last_seen=last_seen,
        )

        enrichment_create.additional_properties = d
        return enrichment_create

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
