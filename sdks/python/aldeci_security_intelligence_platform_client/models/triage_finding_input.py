from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TriageFindingInput")


@_attrs_define
class TriageFindingInput:
    """A single finding to enrich.

    Attributes:
        finding_id (str): Unique finding identifier
        title (str): Finding title
        severity (str): Severity: critical, high, medium, low, info
        cve_id (None | str | Unset): CVE identifier (e.g. CVE-2024-1234)
        cwe_ids (list[str] | None | Unset): CWE identifiers
        asset_name (None | str | Unset): Affected asset
        source (None | str | Unset): Scanner source
        risk_score (float | None | Unset): Numeric risk score 0-100
    """

    finding_id: str
    title: str
    severity: str
    cve_id: None | str | Unset = UNSET
    cwe_ids: list[str] | None | Unset = UNSET
    asset_name: None | str | Unset = UNSET
    source: None | str | Unset = UNSET
    risk_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        title = self.title

        severity = self.severity

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        cwe_ids: list[str] | None | Unset
        if isinstance(self.cwe_ids, Unset):
            cwe_ids = UNSET
        elif isinstance(self.cwe_ids, list):
            cwe_ids = self.cwe_ids

        else:
            cwe_ids = self.cwe_ids

        asset_name: None | str | Unset
        if isinstance(self.asset_name, Unset):
            asset_name = UNSET
        else:
            asset_name = self.asset_name

        source: None | str | Unset
        if isinstance(self.source, Unset):
            source = UNSET
        else:
            source = self.source

        risk_score: float | None | Unset
        if isinstance(self.risk_score, Unset):
            risk_score = UNSET
        else:
            risk_score = self.risk_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "title": title,
                "severity": severity,
            }
        )
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if cwe_ids is not UNSET:
            field_dict["cwe_ids"] = cwe_ids
        if asset_name is not UNSET:
            field_dict["asset_name"] = asset_name
        if source is not UNSET:
            field_dict["source"] = source
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        title = d.pop("title")

        severity = d.pop("severity")

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        def _parse_cwe_ids(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                cwe_ids_type_0 = cast(list[str], data)

                return cwe_ids_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        cwe_ids = _parse_cwe_ids(d.pop("cwe_ids", UNSET))

        def _parse_asset_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_name = _parse_asset_name(d.pop("asset_name", UNSET))

        def _parse_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source = _parse_source(d.pop("source", UNSET))

        def _parse_risk_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        risk_score = _parse_risk_score(d.pop("risk_score", UNSET))

        triage_finding_input = cls(
            finding_id=finding_id,
            title=title,
            severity=severity,
            cve_id=cve_id,
            cwe_ids=cwe_ids,
            asset_name=asset_name,
            source=source,
            risk_score=risk_score,
        )

        triage_finding_input.additional_properties = d
        return triage_finding_input

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
