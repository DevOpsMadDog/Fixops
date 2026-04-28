from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SupplierIn")


@_attrs_define
class SupplierIn:
    """
    Attributes:
        name (str):
        category (str | Unset):  Default: 'software'.
        country (str | Unset):  Default: ''.
        risk_tier (str | Unset):  Default: 'medium'.
        compliance_score (float | Unset):  Default: 0.0.
        last_assessed (None | str | Unset):
        contacts (list[str] | Unset):
    """

    name: str
    category: str | Unset = "software"
    country: str | Unset = ""
    risk_tier: str | Unset = "medium"
    compliance_score: float | Unset = 0.0
    last_assessed: None | str | Unset = UNSET
    contacts: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        category = self.category

        country = self.country

        risk_tier = self.risk_tier

        compliance_score = self.compliance_score

        last_assessed: None | str | Unset
        if isinstance(self.last_assessed, Unset):
            last_assessed = UNSET
        else:
            last_assessed = self.last_assessed

        contacts: list[str] | Unset = UNSET
        if not isinstance(self.contacts, Unset):
            contacts = self.contacts

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if category is not UNSET:
            field_dict["category"] = category
        if country is not UNSET:
            field_dict["country"] = country
        if risk_tier is not UNSET:
            field_dict["risk_tier"] = risk_tier
        if compliance_score is not UNSET:
            field_dict["compliance_score"] = compliance_score
        if last_assessed is not UNSET:
            field_dict["last_assessed"] = last_assessed
        if contacts is not UNSET:
            field_dict["contacts"] = contacts

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        category = d.pop("category", UNSET)

        country = d.pop("country", UNSET)

        risk_tier = d.pop("risk_tier", UNSET)

        compliance_score = d.pop("compliance_score", UNSET)

        def _parse_last_assessed(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_assessed = _parse_last_assessed(d.pop("last_assessed", UNSET))

        contacts = cast(list[str], d.pop("contacts", UNSET))

        supplier_in = cls(
            name=name,
            category=category,
            country=country,
            risk_tier=risk_tier,
            compliance_score=compliance_score,
            last_assessed=last_assessed,
            contacts=contacts,
        )

        supplier_in.additional_properties = d
        return supplier_in

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
