from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddSupplyChainVulnRequest")


@_attrs_define
class AddSupplyChainVulnRequest:
    """Request to add a supply chain vulnerability.

    Attributes:
        vuln_id (str):
        ecosystem (str):
        package_name (str):
        affected_versions (None | str | Unset):
        patched_versions (None | str | Unset):
        severity (str | Unset):  Default: 'unknown'.
        cvss_score (float | None | Unset):
        reachable (bool | None | Unset):
        transitive (bool | Unset):  Default: False.
        source (None | str | Unset):
    """

    vuln_id: str
    ecosystem: str
    package_name: str
    affected_versions: None | str | Unset = UNSET
    patched_versions: None | str | Unset = UNSET
    severity: str | Unset = "unknown"
    cvss_score: float | None | Unset = UNSET
    reachable: bool | None | Unset = UNSET
    transitive: bool | Unset = False
    source: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vuln_id = self.vuln_id

        ecosystem = self.ecosystem

        package_name = self.package_name

        affected_versions: None | str | Unset
        if isinstance(self.affected_versions, Unset):
            affected_versions = UNSET
        else:
            affected_versions = self.affected_versions

        patched_versions: None | str | Unset
        if isinstance(self.patched_versions, Unset):
            patched_versions = UNSET
        else:
            patched_versions = self.patched_versions

        severity = self.severity

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

        reachable: bool | None | Unset
        if isinstance(self.reachable, Unset):
            reachable = UNSET
        else:
            reachable = self.reachable

        transitive = self.transitive

        source: None | str | Unset
        if isinstance(self.source, Unset):
            source = UNSET
        else:
            source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vuln_id": vuln_id,
                "ecosystem": ecosystem,
                "package_name": package_name,
            }
        )
        if affected_versions is not UNSET:
            field_dict["affected_versions"] = affected_versions
        if patched_versions is not UNSET:
            field_dict["patched_versions"] = patched_versions
        if severity is not UNSET:
            field_dict["severity"] = severity
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if reachable is not UNSET:
            field_dict["reachable"] = reachable
        if transitive is not UNSET:
            field_dict["transitive"] = transitive
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vuln_id = d.pop("vuln_id")

        ecosystem = d.pop("ecosystem")

        package_name = d.pop("package_name")

        def _parse_affected_versions(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        affected_versions = _parse_affected_versions(d.pop("affected_versions", UNSET))

        def _parse_patched_versions(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        patched_versions = _parse_patched_versions(d.pop("patched_versions", UNSET))

        severity = d.pop("severity", UNSET)

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

        def _parse_reachable(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        reachable = _parse_reachable(d.pop("reachable", UNSET))

        transitive = d.pop("transitive", UNSET)

        def _parse_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source = _parse_source(d.pop("source", UNSET))

        add_supply_chain_vuln_request = cls(
            vuln_id=vuln_id,
            ecosystem=ecosystem,
            package_name=package_name,
            affected_versions=affected_versions,
            patched_versions=patched_versions,
            severity=severity,
            cvss_score=cvss_score,
            reachable=reachable,
            transitive=transitive,
            source=source,
        )

        add_supply_chain_vuln_request.additional_properties = d
        return add_supply_chain_vuln_request

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
