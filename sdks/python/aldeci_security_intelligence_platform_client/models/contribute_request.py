from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.contribution_program import ContributionProgram
from ..types import UNSET, Unset

T = TypeVar("T", bound="ContributeRequest")


@_attrs_define
class ContributeRequest:
    """Request to submit vulnerability to CVE program.

    Attributes:
        vuln_id (str): ALdeci internal vulnerability ID
        program (ContributionProgram): CVE contribution programs.
        researcher_name (str):
        researcher_email (str):
        organization (None | str | Unset):
        disclosure_timeline (None | str | Unset): Proposed disclosure timeline (e.g., '90 days')
        coordinate_with_vendor (bool | Unset):  Default: True.
        vendor_contact (None | str | Unset):
        additional_references (list[str] | Unset):
    """

    vuln_id: str
    program: ContributionProgram
    researcher_name: str
    researcher_email: str
    organization: None | str | Unset = UNSET
    disclosure_timeline: None | str | Unset = UNSET
    coordinate_with_vendor: bool | Unset = True
    vendor_contact: None | str | Unset = UNSET
    additional_references: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vuln_id = self.vuln_id

        program = self.program.value

        researcher_name = self.researcher_name

        researcher_email = self.researcher_email

        organization: None | str | Unset
        if isinstance(self.organization, Unset):
            organization = UNSET
        else:
            organization = self.organization

        disclosure_timeline: None | str | Unset
        if isinstance(self.disclosure_timeline, Unset):
            disclosure_timeline = UNSET
        else:
            disclosure_timeline = self.disclosure_timeline

        coordinate_with_vendor = self.coordinate_with_vendor

        vendor_contact: None | str | Unset
        if isinstance(self.vendor_contact, Unset):
            vendor_contact = UNSET
        else:
            vendor_contact = self.vendor_contact

        additional_references: list[str] | Unset = UNSET
        if not isinstance(self.additional_references, Unset):
            additional_references = self.additional_references

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vuln_id": vuln_id,
                "program": program,
                "researcher_name": researcher_name,
                "researcher_email": researcher_email,
            }
        )
        if organization is not UNSET:
            field_dict["organization"] = organization
        if disclosure_timeline is not UNSET:
            field_dict["disclosure_timeline"] = disclosure_timeline
        if coordinate_with_vendor is not UNSET:
            field_dict["coordinate_with_vendor"] = coordinate_with_vendor
        if vendor_contact is not UNSET:
            field_dict["vendor_contact"] = vendor_contact
        if additional_references is not UNSET:
            field_dict["additional_references"] = additional_references

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vuln_id = d.pop("vuln_id")

        program = ContributionProgram(d.pop("program"))

        researcher_name = d.pop("researcher_name")

        researcher_email = d.pop("researcher_email")

        def _parse_organization(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        organization = _parse_organization(d.pop("organization", UNSET))

        def _parse_disclosure_timeline(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        disclosure_timeline = _parse_disclosure_timeline(d.pop("disclosure_timeline", UNSET))

        coordinate_with_vendor = d.pop("coordinate_with_vendor", UNSET)

        def _parse_vendor_contact(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        vendor_contact = _parse_vendor_contact(d.pop("vendor_contact", UNSET))

        additional_references = cast(list[str], d.pop("additional_references", UNSET))

        contribute_request = cls(
            vuln_id=vuln_id,
            program=program,
            researcher_name=researcher_name,
            researcher_email=researcher_email,
            organization=organization,
            disclosure_timeline=disclosure_timeline,
            coordinate_with_vendor=coordinate_with_vendor,
            vendor_contact=vendor_contact,
            additional_references=additional_references,
        )

        contribute_request.additional_properties = d
        return contribute_request

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
