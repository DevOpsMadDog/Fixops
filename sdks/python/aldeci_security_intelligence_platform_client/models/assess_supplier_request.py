from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessSupplierRequest")


@_attrs_define
class AssessSupplierRequest:
    """
    Attributes:
        org_id (str | Unset): Organisation identifier Default: 'default'.
        security_certifications (bool | Unset): Supplier holds relevant security certifications Default: False.
        incident_history (bool | Unset): Supplier has a history of incidents Default: False.
        financial_stability (bool | Unset): Supplier is financially stable Default: False.
        compliance_status (bool | Unset): Supplier is compliant with required standards Default: False.
        business_continuity (bool | Unset): Supplier has a business continuity plan Default: False.
    """

    org_id: str | Unset = "default"
    security_certifications: bool | Unset = False
    incident_history: bool | Unset = False
    financial_stability: bool | Unset = False
    compliance_status: bool | Unset = False
    business_continuity: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        security_certifications = self.security_certifications

        incident_history = self.incident_history

        financial_stability = self.financial_stability

        compliance_status = self.compliance_status

        business_continuity = self.business_continuity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if security_certifications is not UNSET:
            field_dict["security_certifications"] = security_certifications
        if incident_history is not UNSET:
            field_dict["incident_history"] = incident_history
        if financial_stability is not UNSET:
            field_dict["financial_stability"] = financial_stability
        if compliance_status is not UNSET:
            field_dict["compliance_status"] = compliance_status
        if business_continuity is not UNSET:
            field_dict["business_continuity"] = business_continuity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        security_certifications = d.pop("security_certifications", UNSET)

        incident_history = d.pop("incident_history", UNSET)

        financial_stability = d.pop("financial_stability", UNSET)

        compliance_status = d.pop("compliance_status", UNSET)

        business_continuity = d.pop("business_continuity", UNSET)

        assess_supplier_request = cls(
            org_id=org_id,
            security_certifications=security_certifications,
            incident_history=incident_history,
            financial_stability=financial_stability,
            compliance_status=compliance_status,
            business_continuity=business_continuity,
        )

        assess_supplier_request.additional_properties = d
        return assess_supplier_request

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
