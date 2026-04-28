from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.data_access_level import DataAccessLevel
from ..models.service_category import ServiceCategory
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.certification_record import CertificationRecord
    from ..models.sla_terms import SLATerms
    from ..models.vendor_contact import VendorContact


T = TypeVar("T", bound="VendorCreateRequest")


@_attrs_define
class VendorCreateRequest:
    """Request body for registering a new vendor.

    Attributes:
        name (str): Vendor name
        service_category (ServiceCategory):
        data_access_level (DataAccessLevel):
        contract_start (str): ISO-8601 contract start date (YYYY-MM-DD)
        contract_end (str): ISO-8601 contract expiry date (YYYY-MM-DD)
        is_core_operations (bool | Unset): True if vendor supports core operations Default: False.
        sla_terms (None | SLATerms | Unset):
        certifications (list[CertificationRecord] | Unset):
        primary_contact (None | Unset | VendorContact):
        description (str | Unset): Brief description of the vendor relationship Default: ''.
        fourth_party_vendors (list[str] | Unset): Vendor IDs used by this vendor (fourth-party dependencies)
    """

    name: str
    service_category: ServiceCategory
    data_access_level: DataAccessLevel
    contract_start: str
    contract_end: str
    is_core_operations: bool | Unset = False
    sla_terms: None | SLATerms | Unset = UNSET
    certifications: list[CertificationRecord] | Unset = UNSET
    primary_contact: None | Unset | VendorContact = UNSET
    description: str | Unset = ""
    fourth_party_vendors: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.sla_terms import SLATerms
        from ..models.vendor_contact import VendorContact

        name = self.name

        service_category = self.service_category.value

        data_access_level = self.data_access_level.value

        contract_start = self.contract_start

        contract_end = self.contract_end

        is_core_operations = self.is_core_operations

        sla_terms: dict[str, Any] | None | Unset
        if isinstance(self.sla_terms, Unset):
            sla_terms = UNSET
        elif isinstance(self.sla_terms, SLATerms):
            sla_terms = self.sla_terms.to_dict()
        else:
            sla_terms = self.sla_terms

        certifications: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.certifications, Unset):
            certifications = []
            for certifications_item_data in self.certifications:
                certifications_item = certifications_item_data.to_dict()
                certifications.append(certifications_item)

        primary_contact: dict[str, Any] | None | Unset
        if isinstance(self.primary_contact, Unset):
            primary_contact = UNSET
        elif isinstance(self.primary_contact, VendorContact):
            primary_contact = self.primary_contact.to_dict()
        else:
            primary_contact = self.primary_contact

        description = self.description

        fourth_party_vendors: list[str] | Unset = UNSET
        if not isinstance(self.fourth_party_vendors, Unset):
            fourth_party_vendors = self.fourth_party_vendors

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "service_category": service_category,
                "data_access_level": data_access_level,
                "contract_start": contract_start,
                "contract_end": contract_end,
            }
        )
        if is_core_operations is not UNSET:
            field_dict["is_core_operations"] = is_core_operations
        if sla_terms is not UNSET:
            field_dict["sla_terms"] = sla_terms
        if certifications is not UNSET:
            field_dict["certifications"] = certifications
        if primary_contact is not UNSET:
            field_dict["primary_contact"] = primary_contact
        if description is not UNSET:
            field_dict["description"] = description
        if fourth_party_vendors is not UNSET:
            field_dict["fourth_party_vendors"] = fourth_party_vendors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.certification_record import CertificationRecord
        from ..models.sla_terms import SLATerms
        from ..models.vendor_contact import VendorContact

        d = dict(src_dict)
        name = d.pop("name")

        service_category = ServiceCategory(d.pop("service_category"))

        data_access_level = DataAccessLevel(d.pop("data_access_level"))

        contract_start = d.pop("contract_start")

        contract_end = d.pop("contract_end")

        is_core_operations = d.pop("is_core_operations", UNSET)

        def _parse_sla_terms(data: object) -> None | SLATerms | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                sla_terms_type_0 = SLATerms.from_dict(data)

                return sla_terms_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SLATerms | Unset, data)

        sla_terms = _parse_sla_terms(d.pop("sla_terms", UNSET))

        _certifications = d.pop("certifications", UNSET)
        certifications: list[CertificationRecord] | Unset = UNSET
        if _certifications is not UNSET:
            certifications = []
            for certifications_item_data in _certifications:
                certifications_item = CertificationRecord.from_dict(certifications_item_data)

                certifications.append(certifications_item)

        def _parse_primary_contact(data: object) -> None | Unset | VendorContact:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                primary_contact_type_0 = VendorContact.from_dict(data)

                return primary_contact_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | VendorContact, data)

        primary_contact = _parse_primary_contact(d.pop("primary_contact", UNSET))

        description = d.pop("description", UNSET)

        fourth_party_vendors = cast(list[str], d.pop("fourth_party_vendors", UNSET))

        vendor_create_request = cls(
            name=name,
            service_category=service_category,
            data_access_level=data_access_level,
            contract_start=contract_start,
            contract_end=contract_end,
            is_core_operations=is_core_operations,
            sla_terms=sla_terms,
            certifications=certifications,
            primary_contact=primary_contact,
            description=description,
            fourth_party_vendors=fourth_party_vendors,
        )

        vendor_create_request.additional_properties = d
        return vendor_create_request

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
