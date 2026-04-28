from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.vendor_tier import VendorTier
from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateVendorRequest")


@_attrs_define
class CreateVendorRequest:
    """Request body for creating or updating a vendor risk assessment.

    Attributes:
        vendor_name (str): Vendor / publisher name
        vendor_url (None | str | Unset):
        tier (VendorTier | Unset):
        org_id (str | Unset):  Default: 'default'.
        security_score (float | Unset):  Default: 50.0.
        sla_uptime_pct (float | None | Unset):
        sla_response_hours (int | None | Unset):
        sla_compliant (bool | Unset):  Default: True.
        known_breaches (int | Unset):  Default: 0.
        breach_details (list[str] | Unset):
        component_count (int | Unset):  Default: 0.
        security_contact (None | str | Unset):
        bug_bounty (bool | Unset):  Default: False.
        mfa_required (bool | Unset):  Default: False.
        sbom_provided (bool | Unset):  Default: False.
        notes (str | Unset):  Default: ''.
    """

    vendor_name: str
    vendor_url: None | str | Unset = UNSET
    tier: VendorTier | Unset = UNSET
    org_id: str | Unset = "default"
    security_score: float | Unset = 50.0
    sla_uptime_pct: float | None | Unset = UNSET
    sla_response_hours: int | None | Unset = UNSET
    sla_compliant: bool | Unset = True
    known_breaches: int | Unset = 0
    breach_details: list[str] | Unset = UNSET
    component_count: int | Unset = 0
    security_contact: None | str | Unset = UNSET
    bug_bounty: bool | Unset = False
    mfa_required: bool | Unset = False
    sbom_provided: bool | Unset = False
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vendor_name = self.vendor_name

        vendor_url: None | str | Unset
        if isinstance(self.vendor_url, Unset):
            vendor_url = UNSET
        else:
            vendor_url = self.vendor_url

        tier: str | Unset = UNSET
        if not isinstance(self.tier, Unset):
            tier = self.tier.value

        org_id = self.org_id

        security_score = self.security_score

        sla_uptime_pct: float | None | Unset
        if isinstance(self.sla_uptime_pct, Unset):
            sla_uptime_pct = UNSET
        else:
            sla_uptime_pct = self.sla_uptime_pct

        sla_response_hours: int | None | Unset
        if isinstance(self.sla_response_hours, Unset):
            sla_response_hours = UNSET
        else:
            sla_response_hours = self.sla_response_hours

        sla_compliant = self.sla_compliant

        known_breaches = self.known_breaches

        breach_details: list[str] | Unset = UNSET
        if not isinstance(self.breach_details, Unset):
            breach_details = self.breach_details

        component_count = self.component_count

        security_contact: None | str | Unset
        if isinstance(self.security_contact, Unset):
            security_contact = UNSET
        else:
            security_contact = self.security_contact

        bug_bounty = self.bug_bounty

        mfa_required = self.mfa_required

        sbom_provided = self.sbom_provided

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor_name": vendor_name,
            }
        )
        if vendor_url is not UNSET:
            field_dict["vendor_url"] = vendor_url
        if tier is not UNSET:
            field_dict["tier"] = tier
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if security_score is not UNSET:
            field_dict["security_score"] = security_score
        if sla_uptime_pct is not UNSET:
            field_dict["sla_uptime_pct"] = sla_uptime_pct
        if sla_response_hours is not UNSET:
            field_dict["sla_response_hours"] = sla_response_hours
        if sla_compliant is not UNSET:
            field_dict["sla_compliant"] = sla_compliant
        if known_breaches is not UNSET:
            field_dict["known_breaches"] = known_breaches
        if breach_details is not UNSET:
            field_dict["breach_details"] = breach_details
        if component_count is not UNSET:
            field_dict["component_count"] = component_count
        if security_contact is not UNSET:
            field_dict["security_contact"] = security_contact
        if bug_bounty is not UNSET:
            field_dict["bug_bounty"] = bug_bounty
        if mfa_required is not UNSET:
            field_dict["mfa_required"] = mfa_required
        if sbom_provided is not UNSET:
            field_dict["sbom_provided"] = sbom_provided
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vendor_name = d.pop("vendor_name")

        def _parse_vendor_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor_url = _parse_vendor_url(d.pop("vendor_url", UNSET))

        _tier = d.pop("tier", UNSET)
        tier: VendorTier | Unset
        if isinstance(_tier, Unset):
            tier = UNSET
        else:
            tier = VendorTier(_tier)

        org_id = d.pop("org_id", UNSET)

        security_score = d.pop("security_score", UNSET)

        def _parse_sla_uptime_pct(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        sla_uptime_pct = _parse_sla_uptime_pct(d.pop("sla_uptime_pct", UNSET))

        def _parse_sla_response_hours(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        sla_response_hours = _parse_sla_response_hours(d.pop("sla_response_hours", UNSET))

        sla_compliant = d.pop("sla_compliant", UNSET)

        known_breaches = d.pop("known_breaches", UNSET)

        breach_details = cast(list[str], d.pop("breach_details", UNSET))

        component_count = d.pop("component_count", UNSET)

        def _parse_security_contact(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        security_contact = _parse_security_contact(d.pop("security_contact", UNSET))

        bug_bounty = d.pop("bug_bounty", UNSET)

        mfa_required = d.pop("mfa_required", UNSET)

        sbom_provided = d.pop("sbom_provided", UNSET)

        notes = d.pop("notes", UNSET)

        create_vendor_request = cls(
            vendor_name=vendor_name,
            vendor_url=vendor_url,
            tier=tier,
            org_id=org_id,
            security_score=security_score,
            sla_uptime_pct=sla_uptime_pct,
            sla_response_hours=sla_response_hours,
            sla_compliant=sla_compliant,
            known_breaches=known_breaches,
            breach_details=breach_details,
            component_count=component_count,
            security_contact=security_contact,
            bug_bounty=bug_bounty,
            mfa_required=mfa_required,
            sbom_provided=sbom_provided,
            notes=notes,
        )

        create_vendor_request.additional_properties = d
        return create_vendor_request

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
