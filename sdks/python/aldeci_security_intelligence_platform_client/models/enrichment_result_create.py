from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnrichmentResultCreate")


@_attrs_define
class EnrichmentResultCreate:
    """
    Attributes:
        source (str):
        reputation_score (float | Unset):  Default: 0.0.
        malicious (bool | Unset):  Default: False.
        tags (list[str] | Unset):
        context (str | Unset):  Default: ''.
        confidence (float | Unset):  Default: 0.0.
        first_seen (None | str | Unset):
        last_seen (None | str | Unset):
    """

    source: str
    reputation_score: float | Unset = 0.0
    malicious: bool | Unset = False
    tags: list[str] | Unset = UNSET
    context: str | Unset = ""
    confidence: float | Unset = 0.0
    first_seen: None | str | Unset = UNSET
    last_seen: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source = self.source

        reputation_score = self.reputation_score

        malicious = self.malicious

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        context = self.context

        confidence = self.confidence

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
                "source": source,
            }
        )
        if reputation_score is not UNSET:
            field_dict["reputation_score"] = reputation_score
        if malicious is not UNSET:
            field_dict["malicious"] = malicious
        if tags is not UNSET:
            field_dict["tags"] = tags
        if context is not UNSET:
            field_dict["context"] = context
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source = d.pop("source")

        reputation_score = d.pop("reputation_score", UNSET)

        malicious = d.pop("malicious", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        context = d.pop("context", UNSET)

        confidence = d.pop("confidence", UNSET)

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

        enrichment_result_create = cls(
            source=source,
            reputation_score=reputation_score,
            malicious=malicious,
            tags=tags,
            context=context,
            confidence=confidence,
            first_seen=first_seen,
            last_seen=last_seen,
        )

        enrichment_result_create.additional_properties = d
        return enrichment_result_create

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
