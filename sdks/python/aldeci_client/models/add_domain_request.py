from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddDomainRequest")


@_attrs_define
class AddDomainRequest:
    """
    Attributes:
        domain (str): Domain name (e.g. example.com)
        org_id (str | Unset): Organisation ID Default: 'default'.
        spf_record (None | str | Unset): SPF TXT record value
        dkim_selector (None | str | Unset): DKIM selector name
        dmarc_policy (None | str | Unset): DMARC policy: none | quarantine | reject | missing
    """

    domain: str
    org_id: str | Unset = "default"
    spf_record: None | str | Unset = UNSET
    dkim_selector: None | str | Unset = UNSET
    dmarc_policy: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain = self.domain

        org_id = self.org_id

        spf_record: None | str | Unset
        if isinstance(self.spf_record, Unset):
            spf_record = UNSET
        else:
            spf_record = self.spf_record

        dkim_selector: None | str | Unset
        if isinstance(self.dkim_selector, Unset):
            dkim_selector = UNSET
        else:
            dkim_selector = self.dkim_selector

        dmarc_policy: None | str | Unset
        if isinstance(self.dmarc_policy, Unset):
            dmarc_policy = UNSET
        else:
            dmarc_policy = self.dmarc_policy

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain": domain,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if spf_record is not UNSET:
            field_dict["spf_record"] = spf_record
        if dkim_selector is not UNSET:
            field_dict["dkim_selector"] = dkim_selector
        if dmarc_policy is not UNSET:
            field_dict["dmarc_policy"] = dmarc_policy

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain = d.pop("domain")

        org_id = d.pop("org_id", UNSET)

        def _parse_spf_record(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        spf_record = _parse_spf_record(d.pop("spf_record", UNSET))

        def _parse_dkim_selector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dkim_selector = _parse_dkim_selector(d.pop("dkim_selector", UNSET))

        def _parse_dmarc_policy(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        dmarc_policy = _parse_dmarc_policy(d.pop("dmarc_policy", UNSET))

        add_domain_request = cls(
            domain=domain,
            org_id=org_id,
            spf_record=spf_record,
            dkim_selector=dkim_selector,
            dmarc_policy=dmarc_policy,
        )

        add_domain_request.additional_properties = d
        return add_domain_request

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
