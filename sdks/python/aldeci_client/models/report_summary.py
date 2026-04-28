from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReportSummary")


@_attrs_define
class ReportSummary:
    """Lightweight report summary (no sections).

    Attributes:
        id (str):
        framework (str):
        title (str):
        generated_at (str):
        score (float):
        gaps_count (int):
        org_id (None | str | Unset):
    """

    id: str
    framework: str
    title: str
    generated_at: str
    score: float
    gaps_count: int
    org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        framework = self.framework

        title = self.title

        generated_at = self.generated_at

        score = self.score

        gaps_count = self.gaps_count

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "framework": framework,
                "title": title,
                "generated_at": generated_at,
                "score": score,
                "gaps_count": gaps_count,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        framework = d.pop("framework")

        title = d.pop("title")

        generated_at = d.pop("generated_at")

        score = d.pop("score")

        gaps_count = d.pop("gaps_count")

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        report_summary = cls(
            id=id,
            framework=framework,
            title=title,
            generated_at=generated_at,
            score=score,
            gaps_count=gaps_count,
            org_id=org_id,
        )

        report_summary.additional_properties = d
        return report_summary

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
