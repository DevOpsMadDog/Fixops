from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MatchCriteria")


@_attrs_define
class MatchCriteria:
    """Criteria fields are AND-combined — all specified fields must match.

    Attributes:
        cve_pattern (None | str | Unset): Regex matched against cve_id
        scanner (None | str | Unset): Exact scanner name match
        severity (None | str | Unset): Exact severity match (critical/high/medium/low/info)
        min_age_days (int | None | Unset): Finding must be at least this many days old
        max_cvss (float | None | Unset): CVSS score must be <= this value
        component_pattern (None | str | Unset): Regex matched against component/package name
    """

    cve_pattern: None | str | Unset = UNSET
    scanner: None | str | Unset = UNSET
    severity: None | str | Unset = UNSET
    min_age_days: int | None | Unset = UNSET
    max_cvss: float | None | Unset = UNSET
    component_pattern: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_pattern: None | str | Unset
        if isinstance(self.cve_pattern, Unset):
            cve_pattern = UNSET
        else:
            cve_pattern = self.cve_pattern

        scanner: None | str | Unset
        if isinstance(self.scanner, Unset):
            scanner = UNSET
        else:
            scanner = self.scanner

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        min_age_days: int | None | Unset
        if isinstance(self.min_age_days, Unset):
            min_age_days = UNSET
        else:
            min_age_days = self.min_age_days

        max_cvss: float | None | Unset
        if isinstance(self.max_cvss, Unset):
            max_cvss = UNSET
        else:
            max_cvss = self.max_cvss

        component_pattern: None | str | Unset
        if isinstance(self.component_pattern, Unset):
            component_pattern = UNSET
        else:
            component_pattern = self.component_pattern

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cve_pattern is not UNSET:
            field_dict["cve_pattern"] = cve_pattern
        if scanner is not UNSET:
            field_dict["scanner"] = scanner
        if severity is not UNSET:
            field_dict["severity"] = severity
        if min_age_days is not UNSET:
            field_dict["min_age_days"] = min_age_days
        if max_cvss is not UNSET:
            field_dict["max_cvss"] = max_cvss
        if component_pattern is not UNSET:
            field_dict["component_pattern"] = component_pattern

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_cve_pattern(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_pattern = _parse_cve_pattern(d.pop("cve_pattern", UNSET))

        def _parse_scanner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scanner = _parse_scanner(d.pop("scanner", UNSET))

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        def _parse_min_age_days(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        min_age_days = _parse_min_age_days(d.pop("min_age_days", UNSET))

        def _parse_max_cvss(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        max_cvss = _parse_max_cvss(d.pop("max_cvss", UNSET))

        def _parse_component_pattern(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        component_pattern = _parse_component_pattern(d.pop("component_pattern", UNSET))

        match_criteria = cls(
            cve_pattern=cve_pattern,
            scanner=scanner,
            severity=severity,
            min_age_days=min_age_days,
            max_cvss=max_cvss,
            component_pattern=component_pattern,
        )

        match_criteria.additional_properties = d
        return match_criteria

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
