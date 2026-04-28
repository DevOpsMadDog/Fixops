from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ComponentCreate")


@_attrs_define
class ComponentCreate:
    """
    Attributes:
        component_name (str):
        component_version (str | Unset):  Default: ''.
        component_type (str | Unset):  Default: 'library'.
        purl (str | Unset):  Default: ''.
        cpe (str | Unset):  Default: ''.
        license_ (str | Unset):  Default: ''.
        supplier (str | Unset):  Default: ''.
        ecosystem (str | Unset):  Default: ''.
        known_vulns (list[str] | Unset):
        risk_score (float | None | Unset):
    """

    component_name: str
    component_version: str | Unset = ""
    component_type: str | Unset = "library"
    purl: str | Unset = ""
    cpe: str | Unset = ""
    license_: str | Unset = ""
    supplier: str | Unset = ""
    ecosystem: str | Unset = ""
    known_vulns: list[str] | Unset = UNSET
    risk_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        component_name = self.component_name

        component_version = self.component_version

        component_type = self.component_type

        purl = self.purl

        cpe = self.cpe

        license_ = self.license_

        supplier = self.supplier

        ecosystem = self.ecosystem

        known_vulns: list[str] | Unset = UNSET
        if not isinstance(self.known_vulns, Unset):
            known_vulns = self.known_vulns

        risk_score: float | None | Unset
        if isinstance(self.risk_score, Unset):
            risk_score = UNSET
        else:
            risk_score = self.risk_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "component_name": component_name,
            }
        )
        if component_version is not UNSET:
            field_dict["component_version"] = component_version
        if component_type is not UNSET:
            field_dict["component_type"] = component_type
        if purl is not UNSET:
            field_dict["purl"] = purl
        if cpe is not UNSET:
            field_dict["cpe"] = cpe
        if license_ is not UNSET:
            field_dict["license"] = license_
        if supplier is not UNSET:
            field_dict["supplier"] = supplier
        if ecosystem is not UNSET:
            field_dict["ecosystem"] = ecosystem
        if known_vulns is not UNSET:
            field_dict["known_vulns"] = known_vulns
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        component_name = d.pop("component_name")

        component_version = d.pop("component_version", UNSET)

        component_type = d.pop("component_type", UNSET)

        purl = d.pop("purl", UNSET)

        cpe = d.pop("cpe", UNSET)

        license_ = d.pop("license", UNSET)

        supplier = d.pop("supplier", UNSET)

        ecosystem = d.pop("ecosystem", UNSET)

        known_vulns = cast(list[str], d.pop("known_vulns", UNSET))

        def _parse_risk_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        risk_score = _parse_risk_score(d.pop("risk_score", UNSET))

        component_create = cls(
            component_name=component_name,
            component_version=component_version,
            component_type=component_type,
            purl=purl,
            cpe=cpe,
            license_=license_,
            supplier=supplier,
            ecosystem=ecosystem,
            known_vulns=known_vulns,
            risk_score=risk_score,
        )

        component_create.additional_properties = d
        return component_create

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
