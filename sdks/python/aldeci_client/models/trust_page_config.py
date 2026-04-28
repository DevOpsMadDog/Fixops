from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TrustPageConfig")


@_attrs_define
class TrustPageConfig:
    """Configuration for a public-facing trust page.

    Attributes:
        org_id (str):
        org_name (str):
        logo_url (None | str | Unset):
        brand_color (str | Unset):  Default: '#0066CC'.
        enabled_sections (list[str] | Unset):
        custom_message (None | str | Unset):
        contact_email (None | str | Unset):
    """

    org_id: str
    org_name: str
    logo_url: None | str | Unset = UNSET
    brand_color: str | Unset = "#0066CC"
    enabled_sections: list[str] | Unset = UNSET
    custom_message: None | str | Unset = UNSET
    contact_email: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        org_name = self.org_name

        logo_url: None | str | Unset
        if isinstance(self.logo_url, Unset):
            logo_url = UNSET
        else:
            logo_url = self.logo_url

        brand_color = self.brand_color

        enabled_sections: list[str] | Unset = UNSET
        if not isinstance(self.enabled_sections, Unset):
            enabled_sections = self.enabled_sections

        custom_message: None | str | Unset
        if isinstance(self.custom_message, Unset):
            custom_message = UNSET
        else:
            custom_message = self.custom_message

        contact_email: None | str | Unset
        if isinstance(self.contact_email, Unset):
            contact_email = UNSET
        else:
            contact_email = self.contact_email

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "org_name": org_name,
            }
        )
        if logo_url is not UNSET:
            field_dict["logo_url"] = logo_url
        if brand_color is not UNSET:
            field_dict["brand_color"] = brand_color
        if enabled_sections is not UNSET:
            field_dict["enabled_sections"] = enabled_sections
        if custom_message is not UNSET:
            field_dict["custom_message"] = custom_message
        if contact_email is not UNSET:
            field_dict["contact_email"] = contact_email

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        org_name = d.pop("org_name")

        def _parse_logo_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        logo_url = _parse_logo_url(d.pop("logo_url", UNSET))

        brand_color = d.pop("brand_color", UNSET)

        enabled_sections = cast(list[str], d.pop("enabled_sections", UNSET))

        def _parse_custom_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        custom_message = _parse_custom_message(d.pop("custom_message", UNSET))

        def _parse_contact_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        contact_email = _parse_contact_email(d.pop("contact_email", UNSET))

        trust_page_config = cls(
            org_id=org_id,
            org_name=org_name,
            logo_url=logo_url,
            brand_color=brand_color,
            enabled_sections=enabled_sections,
            custom_message=custom_message,
            contact_email=contact_email,
        )

        trust_page_config.additional_properties = d
        return trust_page_config

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
