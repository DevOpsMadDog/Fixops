from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RepoSecurityScore")


@_attrs_define
class RepoSecurityScore:
    """Security posture score for a single repository.

    Attributes:
        repo_name (str):
        score (float): Security score 0-100
        grade (str): Letter grade A-F
        finding_count (int):
        critical (int | Unset):  Default: 0.
        high (int | Unset):  Default: 0.
        medium (int | Unset):  Default: 0.
        low (int | Unset):  Default: 0.
        last_scan (None | str | Unset):
        trend (str | Unset): One of: improving, stable, degrading Default: 'stable'.
    """

    repo_name: str
    score: float
    grade: str
    finding_count: int
    critical: int | Unset = 0
    high: int | Unset = 0
    medium: int | Unset = 0
    low: int | Unset = 0
    last_scan: None | str | Unset = UNSET
    trend: str | Unset = "stable"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo_name = self.repo_name

        score = self.score

        grade = self.grade

        finding_count = self.finding_count

        critical = self.critical

        high = self.high

        medium = self.medium

        low = self.low

        last_scan: None | str | Unset
        if isinstance(self.last_scan, Unset):
            last_scan = UNSET
        else:
            last_scan = self.last_scan

        trend = self.trend

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_name": repo_name,
                "score": score,
                "grade": grade,
                "finding_count": finding_count,
            }
        )
        if critical is not UNSET:
            field_dict["critical"] = critical
        if high is not UNSET:
            field_dict["high"] = high
        if medium is not UNSET:
            field_dict["medium"] = medium
        if low is not UNSET:
            field_dict["low"] = low
        if last_scan is not UNSET:
            field_dict["last_scan"] = last_scan
        if trend is not UNSET:
            field_dict["trend"] = trend

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo_name = d.pop("repo_name")

        score = d.pop("score")

        grade = d.pop("grade")

        finding_count = d.pop("finding_count")

        critical = d.pop("critical", UNSET)

        high = d.pop("high", UNSET)

        medium = d.pop("medium", UNSET)

        low = d.pop("low", UNSET)

        def _parse_last_scan(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_scan = _parse_last_scan(d.pop("last_scan", UNSET))

        trend = d.pop("trend", UNSET)

        repo_security_score = cls(
            repo_name=repo_name,
            score=score,
            grade=grade,
            finding_count=finding_count,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            last_scan=last_scan,
            trend=trend,
        )

        repo_security_score.additional_properties = d
        return repo_security_score

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
