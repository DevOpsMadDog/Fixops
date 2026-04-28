from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="FullScanRequest")


@_attrs_define
class FullScanRequest:
    """Body for triggering a full external risk scan.

    Attributes:
        org_id (str): Organisation identifier
        domain (str): Primary domain to scan (e.g. acme.io)
        email_domain (str): Email domain for credential probe (e.g. acme.io)
    """

    org_id: str
    domain: str
    email_domain: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        domain = self.domain

        email_domain = self.email_domain

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "domain": domain,
                "email_domain": email_domain,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        domain = d.pop("domain")

        email_domain = d.pop("email_domain")

        full_scan_request = cls(
            org_id=org_id,
            domain=domain,
            email_domain=email_domain,
        )

        full_scan_request.additional_properties = d
        return full_scan_request

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
