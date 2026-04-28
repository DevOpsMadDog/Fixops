from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddThreatActorMappingRequest")


@_attrs_define
class AddThreatActorMappingRequest:
    """Request to add a threat actor to CVE mapping.

    Attributes:
        cve_id (str):
        threat_actor (str):
        campaign (None | str | Unset):
        first_seen (None | str | Unset):
        last_seen (None | str | Unset):
        target_sectors (list[str] | None | Unset):
        target_countries (list[str] | None | Unset):
        ttps (list[str] | None | Unset):
        confidence (str | Unset): low, medium, high Default: 'medium'.
        source (None | str | Unset):
    """

    cve_id: str
    threat_actor: str
    campaign: None | str | Unset = UNSET
    first_seen: None | str | Unset = UNSET
    last_seen: None | str | Unset = UNSET
    target_sectors: list[str] | None | Unset = UNSET
    target_countries: list[str] | None | Unset = UNSET
    ttps: list[str] | None | Unset = UNSET
    confidence: str | Unset = "medium"
    source: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        threat_actor = self.threat_actor

        campaign: None | str | Unset
        if isinstance(self.campaign, Unset):
            campaign = UNSET
        else:
            campaign = self.campaign

        first_seen: None | str | Unset
        if isinstance(self.first_seen, Unset):
            first_seen = UNSET
        else:
            first_seen = self.first_seen

        last_seen: None | str | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        target_sectors: list[str] | None | Unset
        if isinstance(self.target_sectors, Unset):
            target_sectors = UNSET
        elif isinstance(self.target_sectors, list):
            target_sectors = self.target_sectors

        else:
            target_sectors = self.target_sectors

        target_countries: list[str] | None | Unset
        if isinstance(self.target_countries, Unset):
            target_countries = UNSET
        elif isinstance(self.target_countries, list):
            target_countries = self.target_countries

        else:
            target_countries = self.target_countries

        ttps: list[str] | None | Unset
        if isinstance(self.ttps, Unset):
            ttps = UNSET
        elif isinstance(self.ttps, list):
            ttps = self.ttps

        else:
            ttps = self.ttps

        confidence = self.confidence

        source: None | str | Unset
        if isinstance(self.source, Unset):
            source = UNSET
        else:
            source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "threat_actor": threat_actor,
            }
        )
        if campaign is not UNSET:
            field_dict["campaign"] = campaign
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen
        if target_sectors is not UNSET:
            field_dict["target_sectors"] = target_sectors
        if target_countries is not UNSET:
            field_dict["target_countries"] = target_countries
        if ttps is not UNSET:
            field_dict["ttps"] = ttps
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        threat_actor = d.pop("threat_actor")

        def _parse_campaign(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        campaign = _parse_campaign(d.pop("campaign", UNSET))

        def _parse_first_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_seen = _parse_first_seen(d.pop("first_seen", UNSET))

        def _parse_last_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        def _parse_target_sectors(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                target_sectors_type_0 = cast(list[str], data)

                return target_sectors_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        target_sectors = _parse_target_sectors(d.pop("target_sectors", UNSET))

        def _parse_target_countries(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                target_countries_type_0 = cast(list[str], data)

                return target_countries_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        target_countries = _parse_target_countries(d.pop("target_countries", UNSET))

        def _parse_ttps(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                ttps_type_0 = cast(list[str], data)

                return ttps_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        ttps = _parse_ttps(d.pop("ttps", UNSET))

        confidence = d.pop("confidence", UNSET)

        def _parse_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source = _parse_source(d.pop("source", UNSET))

        add_threat_actor_mapping_request = cls(
            cve_id=cve_id,
            threat_actor=threat_actor,
            campaign=campaign,
            first_seen=first_seen,
            last_seen=last_seen,
            target_sectors=target_sectors,
            target_countries=target_countries,
            ttps=ttps,
            confidence=confidence,
            source=source,
        )

        add_threat_actor_mapping_request.additional_properties = d
        return add_threat_actor_mapping_request

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
