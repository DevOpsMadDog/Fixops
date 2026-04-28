from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddThreatRequest")


@_attrs_define
class AddThreatRequest:
    """
    Attributes:
        threat_name (str): Threat name (required)
        threat_actor (None | str | Unset): Threat actor / APT group
        severity (str | Unset): critical | high | medium | low | informational Default: 'medium'.
        affected_sectors (list[str] | None | Unset): Affected industry sectors
        ioc_count (int | Unset): Number of IOCs associated Default: 0.
        mitre_tactics (list[str] | None | Unset): MITRE ATT&CK tactics
    """

    threat_name: str
    threat_actor: None | str | Unset = UNSET
    severity: str | Unset = "medium"
    affected_sectors: list[str] | None | Unset = UNSET
    ioc_count: int | Unset = 0
    mitre_tactics: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        threat_name = self.threat_name

        threat_actor: None | str | Unset
        if isinstance(self.threat_actor, Unset):
            threat_actor = UNSET
        else:
            threat_actor = self.threat_actor

        severity = self.severity

        affected_sectors: list[str] | None | Unset
        if isinstance(self.affected_sectors, Unset):
            affected_sectors = UNSET
        elif isinstance(self.affected_sectors, list):
            affected_sectors = self.affected_sectors

        else:
            affected_sectors = self.affected_sectors

        ioc_count = self.ioc_count

        mitre_tactics: list[str] | None | Unset
        if isinstance(self.mitre_tactics, Unset):
            mitre_tactics = UNSET
        elif isinstance(self.mitre_tactics, list):
            mitre_tactics = self.mitre_tactics

        else:
            mitre_tactics = self.mitre_tactics

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "threat_name": threat_name,
            }
        )
        if threat_actor is not UNSET:
            field_dict["threat_actor"] = threat_actor
        if severity is not UNSET:
            field_dict["severity"] = severity
        if affected_sectors is not UNSET:
            field_dict["affected_sectors"] = affected_sectors
        if ioc_count is not UNSET:
            field_dict["ioc_count"] = ioc_count
        if mitre_tactics is not UNSET:
            field_dict["mitre_tactics"] = mitre_tactics

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        threat_name = d.pop("threat_name")

        def _parse_threat_actor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        threat_actor = _parse_threat_actor(d.pop("threat_actor", UNSET))

        severity = d.pop("severity", UNSET)

        def _parse_affected_sectors(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                affected_sectors_type_0 = cast(list[str], data)

                return affected_sectors_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        affected_sectors = _parse_affected_sectors(d.pop("affected_sectors", UNSET))

        ioc_count = d.pop("ioc_count", UNSET)

        def _parse_mitre_tactics(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                mitre_tactics_type_0 = cast(list[str], data)

                return mitre_tactics_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        mitre_tactics = _parse_mitre_tactics(d.pop("mitre_tactics", UNSET))

        add_threat_request = cls(
            threat_name=threat_name,
            threat_actor=threat_actor,
            severity=severity,
            affected_sectors=affected_sectors,
            ioc_count=ioc_count,
            mitre_tactics=mitre_tactics,
        )

        add_threat_request.additional_properties = d
        return add_threat_request

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
