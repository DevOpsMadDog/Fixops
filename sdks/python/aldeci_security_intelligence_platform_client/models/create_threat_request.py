from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateThreatRequest")


@_attrs_define
class CreateThreatRequest:
    """
    Attributes:
        org_id (str | Unset): Organisation ID Default: 'default'.
        domain_id (None | str | Unset): Associated domain ID
        threat_type (str | Unset): phishing | spoofing | bec | spam | malware Default: 'phishing'.
        source_ip (str | Unset): Source IP address of the threat Default: ''.
        sender (str | Unset): Sender email address Default: ''.
        subject_preview (str | Unset): Email subject preview (truncated) Default: ''.
        similarity_score (float | Unset): Domain similarity score (0-1) Default: 0.0.
        status (str | Unset): detected | blocked | quarantined | released Default: 'detected'.
    """

    org_id: str | Unset = "default"
    domain_id: None | str | Unset = UNSET
    threat_type: str | Unset = "phishing"
    source_ip: str | Unset = ""
    sender: str | Unset = ""
    subject_preview: str | Unset = ""
    similarity_score: float | Unset = 0.0
    status: str | Unset = "detected"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        domain_id: None | str | Unset
        if isinstance(self.domain_id, Unset):
            domain_id = UNSET
        else:
            domain_id = self.domain_id

        threat_type = self.threat_type

        source_ip = self.source_ip

        sender = self.sender

        subject_preview = self.subject_preview

        similarity_score = self.similarity_score

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if domain_id is not UNSET:
            field_dict["domain_id"] = domain_id
        if threat_type is not UNSET:
            field_dict["threat_type"] = threat_type
        if source_ip is not UNSET:
            field_dict["source_ip"] = source_ip
        if sender is not UNSET:
            field_dict["sender"] = sender
        if subject_preview is not UNSET:
            field_dict["subject_preview"] = subject_preview
        if similarity_score is not UNSET:
            field_dict["similarity_score"] = similarity_score
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        def _parse_domain_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        domain_id = _parse_domain_id(d.pop("domain_id", UNSET))

        threat_type = d.pop("threat_type", UNSET)

        source_ip = d.pop("source_ip", UNSET)

        sender = d.pop("sender", UNSET)

        subject_preview = d.pop("subject_preview", UNSET)

        similarity_score = d.pop("similarity_score", UNSET)

        status = d.pop("status", UNSET)

        create_threat_request = cls(
            org_id=org_id,
            domain_id=domain_id,
            threat_type=threat_type,
            source_ip=source_ip,
            sender=sender,
            subject_preview=subject_preview,
            similarity_score=similarity_score,
            status=status,
        )

        create_threat_request.additional_properties = d
        return create_threat_request

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
