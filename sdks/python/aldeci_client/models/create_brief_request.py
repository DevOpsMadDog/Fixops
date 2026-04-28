from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateBriefRequest")


@_attrs_define
class CreateBriefRequest:
    """
    Attributes:
        title (str): Brief title (required)
        brief_type (str | Unset): daily | weekly | monthly | incident | executive | technical Default: 'daily'.
        threat_level (str | Unset): critical | high | medium | low | informational Default: 'medium'.
        summary (None | str | Unset): Executive summary
        key_findings (list[str] | None | Unset): List of key findings
        recommendations (list[str] | None | Unset): List of recommendations
        distribution_status (str | Unset): draft | pending | distributed | recalled Default: 'draft'.
        author (None | str | Unset): Author name or ID
        period_start (None | str | Unset): Period start (ISO 8601)
        period_end (None | str | Unset): Period end (ISO 8601)
    """

    title: str
    brief_type: str | Unset = "daily"
    threat_level: str | Unset = "medium"
    summary: None | str | Unset = UNSET
    key_findings: list[str] | None | Unset = UNSET
    recommendations: list[str] | None | Unset = UNSET
    distribution_status: str | Unset = "draft"
    author: None | str | Unset = UNSET
    period_start: None | str | Unset = UNSET
    period_end: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        brief_type = self.brief_type

        threat_level = self.threat_level

        summary: None | str | Unset
        if isinstance(self.summary, Unset):
            summary = UNSET
        else:
            summary = self.summary

        key_findings: list[str] | None | Unset
        if isinstance(self.key_findings, Unset):
            key_findings = UNSET
        elif isinstance(self.key_findings, list):
            key_findings = self.key_findings

        else:
            key_findings = self.key_findings

        recommendations: list[str] | None | Unset
        if isinstance(self.recommendations, Unset):
            recommendations = UNSET
        elif isinstance(self.recommendations, list):
            recommendations = self.recommendations

        else:
            recommendations = self.recommendations

        distribution_status = self.distribution_status

        author: None | str | Unset
        if isinstance(self.author, Unset):
            author = UNSET
        else:
            author = self.author

        period_start: None | str | Unset
        if isinstance(self.period_start, Unset):
            period_start = UNSET
        else:
            period_start = self.period_start

        period_end: None | str | Unset
        if isinstance(self.period_end, Unset):
            period_end = UNSET
        else:
            period_end = self.period_end

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if brief_type is not UNSET:
            field_dict["brief_type"] = brief_type
        if threat_level is not UNSET:
            field_dict["threat_level"] = threat_level
        if summary is not UNSET:
            field_dict["summary"] = summary
        if key_findings is not UNSET:
            field_dict["key_findings"] = key_findings
        if recommendations is not UNSET:
            field_dict["recommendations"] = recommendations
        if distribution_status is not UNSET:
            field_dict["distribution_status"] = distribution_status
        if author is not UNSET:
            field_dict["author"] = author
        if period_start is not UNSET:
            field_dict["period_start"] = period_start
        if period_end is not UNSET:
            field_dict["period_end"] = period_end

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        brief_type = d.pop("brief_type", UNSET)

        threat_level = d.pop("threat_level", UNSET)

        def _parse_summary(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        summary = _parse_summary(d.pop("summary", UNSET))

        def _parse_key_findings(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                key_findings_type_0 = cast(list[str], data)

                return key_findings_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        key_findings = _parse_key_findings(d.pop("key_findings", UNSET))

        def _parse_recommendations(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                recommendations_type_0 = cast(list[str], data)

                return recommendations_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        recommendations = _parse_recommendations(d.pop("recommendations", UNSET))

        distribution_status = d.pop("distribution_status", UNSET)

        def _parse_author(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        author = _parse_author(d.pop("author", UNSET))

        def _parse_period_start(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        period_start = _parse_period_start(d.pop("period_start", UNSET))

        def _parse_period_end(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        period_end = _parse_period_end(d.pop("period_end", UNSET))

        create_brief_request = cls(
            title=title,
            brief_type=brief_type,
            threat_level=threat_level,
            summary=summary,
            key_findings=key_findings,
            recommendations=recommendations,
            distribution_status=distribution_status,
            author=author,
            period_start=period_start,
            period_end=period_end,
        )

        create_brief_request.additional_properties = d
        return create_brief_request

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
