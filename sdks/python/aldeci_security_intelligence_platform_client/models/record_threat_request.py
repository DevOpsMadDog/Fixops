from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordThreatRequest")


@_attrs_define
class RecordThreatRequest:
    """
    Attributes:
        threat_type (str): Type: rogue_ap, evil_twin, deauth_attack, krack, pmkid, wardriving, eavesdropping
        severity (str): Severity: low, medium, high, critical
        org_id (str | Unset):  Default: 'default'.
        ap_id (None | str | Unset):
        bssid (None | str | Unset):
        description (None | str | Unset):
    """

    threat_type: str
    severity: str
    org_id: str | Unset = "default"
    ap_id: None | str | Unset = UNSET
    bssid: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        threat_type = self.threat_type

        severity = self.severity

        org_id = self.org_id

        ap_id: None | str | Unset
        if isinstance(self.ap_id, Unset):
            ap_id = UNSET
        else:
            ap_id = self.ap_id

        bssid: None | str | Unset
        if isinstance(self.bssid, Unset):
            bssid = UNSET
        else:
            bssid = self.bssid

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "threat_type": threat_type,
                "severity": severity,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if ap_id is not UNSET:
            field_dict["ap_id"] = ap_id
        if bssid is not UNSET:
            field_dict["bssid"] = bssid
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        threat_type = d.pop("threat_type")

        severity = d.pop("severity")

        org_id = d.pop("org_id", UNSET)

        def _parse_ap_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ap_id = _parse_ap_id(d.pop("ap_id", UNSET))

        def _parse_bssid(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        bssid = _parse_bssid(d.pop("bssid", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        record_threat_request = cls(
            threat_type=threat_type,
            severity=severity,
            org_id=org_id,
            ap_id=ap_id,
            bssid=bssid,
            description=description,
        )

        record_threat_request.additional_properties = d
        return record_threat_request

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
