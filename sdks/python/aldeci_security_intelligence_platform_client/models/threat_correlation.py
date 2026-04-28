from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.campaign import Campaign
    from ..models.threat_actor import ThreatActor


T = TypeVar("T", bound="ThreatCorrelation")


@_attrs_define
class ThreatCorrelation:
    """Result of correlating a finding against threat intelligence.

    Attributes:
        finding_id: The finding being correlated
        threat_actor: Matched threat actor (None if no match)
        campaign: Matched campaign (None if no match)
        confidence: Confidence score 0.0–1.0
        ioc_matches: IOCs from the finding that matched the actor/campaign
        ttp_matches: TTPs from the finding that matched the actor/campaign

        Attributes:
            finding_id (str):
            threat_actor (None | ThreatActor | Unset):
            campaign (Campaign | None | Unset):
            confidence (float | Unset):  Default: 0.0.
            ioc_matches (list[str] | Unset):
            ttp_matches (list[str] | Unset):
    """

    finding_id: str
    threat_actor: None | ThreatActor | Unset = UNSET
    campaign: Campaign | None | Unset = UNSET
    confidence: float | Unset = 0.0
    ioc_matches: list[str] | Unset = UNSET
    ttp_matches: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.campaign import Campaign
        from ..models.threat_actor import ThreatActor

        finding_id = self.finding_id

        threat_actor: dict[str, Any] | None | Unset
        if isinstance(self.threat_actor, Unset):
            threat_actor = UNSET
        elif isinstance(self.threat_actor, ThreatActor):
            threat_actor = self.threat_actor.to_dict()
        else:
            threat_actor = self.threat_actor

        campaign: dict[str, Any] | None | Unset
        if isinstance(self.campaign, Unset):
            campaign = UNSET
        elif isinstance(self.campaign, Campaign):
            campaign = self.campaign.to_dict()
        else:
            campaign = self.campaign

        confidence = self.confidence

        ioc_matches: list[str] | Unset = UNSET
        if not isinstance(self.ioc_matches, Unset):
            ioc_matches = self.ioc_matches

        ttp_matches: list[str] | Unset = UNSET
        if not isinstance(self.ttp_matches, Unset):
            ttp_matches = self.ttp_matches

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
            }
        )
        if threat_actor is not UNSET:
            field_dict["threat_actor"] = threat_actor
        if campaign is not UNSET:
            field_dict["campaign"] = campaign
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if ioc_matches is not UNSET:
            field_dict["ioc_matches"] = ioc_matches
        if ttp_matches is not UNSET:
            field_dict["ttp_matches"] = ttp_matches

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.campaign import Campaign
        from ..models.threat_actor import ThreatActor

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        def _parse_threat_actor(data: object) -> None | ThreatActor | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                threat_actor_type_0 = ThreatActor.from_dict(data)

                return threat_actor_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ThreatActor | Unset, data)

        threat_actor = _parse_threat_actor(d.pop("threat_actor", UNSET))

        def _parse_campaign(data: object) -> Campaign | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                campaign_type_0 = Campaign.from_dict(data)

                return campaign_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(Campaign | None | Unset, data)

        campaign = _parse_campaign(d.pop("campaign", UNSET))

        confidence = d.pop("confidence", UNSET)

        ioc_matches = cast(list[str], d.pop("ioc_matches", UNSET))

        ttp_matches = cast(list[str], d.pop("ttp_matches", UNSET))

        threat_correlation = cls(
            finding_id=finding_id,
            threat_actor=threat_actor,
            campaign=campaign,
            confidence=confidence,
            ioc_matches=ioc_matches,
            ttp_matches=ttp_matches,
        )

        threat_correlation.additional_properties = d
        return threat_correlation

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
