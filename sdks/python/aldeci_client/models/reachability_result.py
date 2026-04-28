from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.reachability_level import ReachabilityLevel
from ..types import UNSET, Unset

T = TypeVar("T", bound="ReachabilityResult")


@_attrs_define
class ReachabilityResult:
    """Reachability analysis for a finding.

    Attributes:
        finding_id (str):
        level (ReachabilityLevel): Execution path reachability for the vulnerable code.
        call_path (list[str] | Unset): Call graph path to vuln code
        evidence (str | Unset):  Default: ''.
        analyzer (str | Unset):  Default: 'static_analysis'.
        analyzed_at (datetime.datetime | Unset):
    """

    finding_id: str
    level: ReachabilityLevel
    call_path: list[str] | Unset = UNSET
    evidence: str | Unset = ""
    analyzer: str | Unset = "static_analysis"
    analyzed_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        level = self.level.value

        call_path: list[str] | Unset = UNSET
        if not isinstance(self.call_path, Unset):
            call_path = self.call_path

        evidence = self.evidence

        analyzer = self.analyzer

        analyzed_at: str | Unset = UNSET
        if not isinstance(self.analyzed_at, Unset):
            analyzed_at = self.analyzed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "level": level,
            }
        )
        if call_path is not UNSET:
            field_dict["call_path"] = call_path
        if evidence is not UNSET:
            field_dict["evidence"] = evidence
        if analyzer is not UNSET:
            field_dict["analyzer"] = analyzer
        if analyzed_at is not UNSET:
            field_dict["analyzed_at"] = analyzed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        level = ReachabilityLevel(d.pop("level"))

        call_path = cast(list[str], d.pop("call_path", UNSET))

        evidence = d.pop("evidence", UNSET)

        analyzer = d.pop("analyzer", UNSET)

        _analyzed_at = d.pop("analyzed_at", UNSET)
        analyzed_at: datetime.datetime | Unset
        if isinstance(_analyzed_at, Unset):
            analyzed_at = UNSET
        else:
            analyzed_at = isoparse(_analyzed_at)

        reachability_result = cls(
            finding_id=finding_id,
            level=level,
            call_path=call_path,
            evidence=evidence,
            analyzer=analyzer,
            analyzed_at=analyzed_at,
        )

        reachability_result.additional_properties = d
        return reachability_result

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
