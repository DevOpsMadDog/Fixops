from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddDomainThreatRequest")


@_attrs_define
class AddDomainThreatRequest:
    """
    Attributes:
        domain (str): Domain to mark as malicious
        threat_type (str): Threat type: c2/phishing/malware/spam/botnet
        org_id (str | Unset): Organisation ID Default: 'default'.
        confidence (float | Unset): Confidence score 0-1 Default: 0.5.
        source (str | Unset): Source of the intelligence Default: 'manual'.
        iocs (list[str] | Unset): Associated IOCs
    """

    domain: str
    threat_type: str
    org_id: str | Unset = "default"
    confidence: float | Unset = 0.5
    source: str | Unset = "manual"
    iocs: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain = self.domain

        threat_type = self.threat_type

        org_id = self.org_id

        confidence = self.confidence

        source = self.source

        iocs: list[str] | Unset = UNSET
        if not isinstance(self.iocs, Unset):
            iocs = self.iocs

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain": domain,
                "threat_type": threat_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if source is not UNSET:
            field_dict["source"] = source
        if iocs is not UNSET:
            field_dict["iocs"] = iocs

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain = d.pop("domain")

        threat_type = d.pop("threat_type")

        org_id = d.pop("org_id", UNSET)

        confidence = d.pop("confidence", UNSET)

        source = d.pop("source", UNSET)

        iocs = cast(list[str], d.pop("iocs", UNSET))

        add_domain_threat_request = cls(
            domain=domain,
            threat_type=threat_type,
            org_id=org_id,
            confidence=confidence,
            source=source,
            iocs=iocs,
        )

        add_domain_threat_request.additional_properties = d
        return add_domain_threat_request

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
