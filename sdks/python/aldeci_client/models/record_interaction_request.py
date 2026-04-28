from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordInteractionRequest")


@_attrs_define
class RecordInteractionRequest:
    """
    Attributes:
        asset_id (str): ID of the triggered deception asset
        source_ip (str): Attacker source IP address
        attacker_technique (str | Unset): recon | lateral_movement | credential_access | execution | persistence |
            exfiltration | discovery | collection | impact Default: 'recon'.
        confidence_score (float | Unset):  Default: 0.0.
        threat_actor_signature (str | Unset):  Default: ''.
        severity (str | Unset): critical | high | medium | low Default: 'medium'.
        details (str | Unset):  Default: ''.
        detected_at (None | str | Unset):
    """

    asset_id: str
    source_ip: str
    attacker_technique: str | Unset = "recon"
    confidence_score: float | Unset = 0.0
    threat_actor_signature: str | Unset = ""
    severity: str | Unset = "medium"
    details: str | Unset = ""
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        source_ip = self.source_ip

        attacker_technique = self.attacker_technique

        confidence_score = self.confidence_score

        threat_actor_signature = self.threat_actor_signature

        severity = self.severity

        details = self.details

        detected_at: None | str | Unset
        if isinstance(self.detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_id": asset_id,
                "source_ip": source_ip,
            }
        )
        if attacker_technique is not UNSET:
            field_dict["attacker_technique"] = attacker_technique
        if confidence_score is not UNSET:
            field_dict["confidence_score"] = confidence_score
        if threat_actor_signature is not UNSET:
            field_dict["threat_actor_signature"] = threat_actor_signature
        if severity is not UNSET:
            field_dict["severity"] = severity
        if details is not UNSET:
            field_dict["details"] = details
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_id = d.pop("asset_id")

        source_ip = d.pop("source_ip")

        attacker_technique = d.pop("attacker_technique", UNSET)

        confidence_score = d.pop("confidence_score", UNSET)

        threat_actor_signature = d.pop("threat_actor_signature", UNSET)

        severity = d.pop("severity", UNSET)

        details = d.pop("details", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        record_interaction_request = cls(
            asset_id=asset_id,
            source_ip=source_ip,
            attacker_technique=attacker_technique,
            confidence_score=confidence_score,
            threat_actor_signature=threat_actor_signature,
            severity=severity,
            details=details,
            detected_at=detected_at,
        )

        record_interaction_request.additional_properties = d
        return record_interaction_request

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
