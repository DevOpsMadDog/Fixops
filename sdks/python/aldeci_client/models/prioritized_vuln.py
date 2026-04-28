from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.reachability_level import ReachabilityLevel
from ..models.risk_bucket import RiskBucket
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.remediation_recommendation import RemediationRecommendation


T = TypeVar("T", bound="PrioritizedVuln")


@_attrs_define
class PrioritizedVuln:
    """A vulnerability with full composite priority score.

    Attributes:
        finding_id (str):
        title (str):
        asset_id (str):
        asset_name (str):
        id (str | Unset):
        cve_id (None | str | Unset):
        epss_score (float | Unset):  Default: 0.0.
        reachability (ReachabilityLevel | Unset): Execution path reachability for the vulnerable code.
        reachability_factor (float | Unset):  Default: 0.5.
        business_impact (float | Unset):  Default: 0.5.
        compensating_controls (float | Unset):  Default: 0.0.
        composite_score (float | Unset):  Default: 0.0.
        risk_bucket (RiskBucket | Unset): Risk severity bucket for a prioritized vulnerability.
        sla_deadline (datetime.datetime | None | Unset):
        sla_breached (bool | Unset):  Default: False.
        days_open (int | Unset):  Default: 0.
        assigned_team (None | str | Unset):
        group_id (None | str | Unset):
        recommendations (list[RemediationRecommendation] | Unset):
        discovered_at (datetime.datetime | Unset):
        last_prioritized (datetime.datetime | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    finding_id: str
    title: str
    asset_id: str
    asset_name: str
    id: str | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    epss_score: float | Unset = 0.0
    reachability: ReachabilityLevel | Unset = UNSET
    reachability_factor: float | Unset = 0.5
    business_impact: float | Unset = 0.5
    compensating_controls: float | Unset = 0.0
    composite_score: float | Unset = 0.0
    risk_bucket: RiskBucket | Unset = UNSET
    sla_deadline: datetime.datetime | None | Unset = UNSET
    sla_breached: bool | Unset = False
    days_open: int | Unset = 0
    assigned_team: None | str | Unset = UNSET
    group_id: None | str | Unset = UNSET
    recommendations: list[RemediationRecommendation] | Unset = UNSET
    discovered_at: datetime.datetime | Unset = UNSET
    last_prioritized: datetime.datetime | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        title = self.title

        asset_id = self.asset_id

        asset_name = self.asset_name

        id = self.id

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        epss_score = self.epss_score

        reachability: str | Unset = UNSET
        if not isinstance(self.reachability, Unset):
            reachability = self.reachability.value

        reachability_factor = self.reachability_factor

        business_impact = self.business_impact

        compensating_controls = self.compensating_controls

        composite_score = self.composite_score

        risk_bucket: str | Unset = UNSET
        if not isinstance(self.risk_bucket, Unset):
            risk_bucket = self.risk_bucket.value

        sla_deadline: None | str | Unset
        if isinstance(self.sla_deadline, Unset):
            sla_deadline = UNSET
        elif isinstance(self.sla_deadline, datetime.datetime):
            sla_deadline = self.sla_deadline.isoformat()
        else:
            sla_deadline = self.sla_deadline

        sla_breached = self.sla_breached

        days_open = self.days_open

        assigned_team: None | str | Unset
        if isinstance(self.assigned_team, Unset):
            assigned_team = UNSET
        else:
            assigned_team = self.assigned_team

        group_id: None | str | Unset
        if isinstance(self.group_id, Unset):
            group_id = UNSET
        else:
            group_id = self.group_id

        recommendations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.recommendations, Unset):
            recommendations = []
            for recommendations_item_data in self.recommendations:
                recommendations_item = recommendations_item_data.to_dict()
                recommendations.append(recommendations_item)

        discovered_at: str | Unset = UNSET
        if not isinstance(self.discovered_at, Unset):
            discovered_at = self.discovered_at.isoformat()

        last_prioritized: str | Unset = UNSET
        if not isinstance(self.last_prioritized, Unset):
            last_prioritized = self.last_prioritized.isoformat()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "title": title,
                "asset_id": asset_id,
                "asset_name": asset_name,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if reachability is not UNSET:
            field_dict["reachability"] = reachability
        if reachability_factor is not UNSET:
            field_dict["reachability_factor"] = reachability_factor
        if business_impact is not UNSET:
            field_dict["business_impact"] = business_impact
        if compensating_controls is not UNSET:
            field_dict["compensating_controls"] = compensating_controls
        if composite_score is not UNSET:
            field_dict["composite_score"] = composite_score
        if risk_bucket is not UNSET:
            field_dict["risk_bucket"] = risk_bucket
        if sla_deadline is not UNSET:
            field_dict["sla_deadline"] = sla_deadline
        if sla_breached is not UNSET:
            field_dict["sla_breached"] = sla_breached
        if days_open is not UNSET:
            field_dict["days_open"] = days_open
        if assigned_team is not UNSET:
            field_dict["assigned_team"] = assigned_team
        if group_id is not UNSET:
            field_dict["group_id"] = group_id
        if recommendations is not UNSET:
            field_dict["recommendations"] = recommendations
        if discovered_at is not UNSET:
            field_dict["discovered_at"] = discovered_at
        if last_prioritized is not UNSET:
            field_dict["last_prioritized"] = last_prioritized
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.remediation_recommendation import RemediationRecommendation

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        title = d.pop("title")

        asset_id = d.pop("asset_id")

        asset_name = d.pop("asset_name")

        id = d.pop("id", UNSET)

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        epss_score = d.pop("epss_score", UNSET)

        _reachability = d.pop("reachability", UNSET)
        reachability: ReachabilityLevel | Unset
        if isinstance(_reachability, Unset):
            reachability = UNSET
        else:
            reachability = ReachabilityLevel(_reachability)

        reachability_factor = d.pop("reachability_factor", UNSET)

        business_impact = d.pop("business_impact", UNSET)

        compensating_controls = d.pop("compensating_controls", UNSET)

        composite_score = d.pop("composite_score", UNSET)

        _risk_bucket = d.pop("risk_bucket", UNSET)
        risk_bucket: RiskBucket | Unset
        if isinstance(_risk_bucket, Unset):
            risk_bucket = UNSET
        else:
            risk_bucket = RiskBucket(_risk_bucket)

        def _parse_sla_deadline(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                sla_deadline_type_0 = isoparse(data)

                return sla_deadline_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        sla_deadline = _parse_sla_deadline(d.pop("sla_deadline", UNSET))

        sla_breached = d.pop("sla_breached", UNSET)

        days_open = d.pop("days_open", UNSET)

        def _parse_assigned_team(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assigned_team = _parse_assigned_team(d.pop("assigned_team", UNSET))

        def _parse_group_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        group_id = _parse_group_id(d.pop("group_id", UNSET))

        _recommendations = d.pop("recommendations", UNSET)
        recommendations: list[RemediationRecommendation] | Unset = UNSET
        if _recommendations is not UNSET:
            recommendations = []
            for recommendations_item_data in _recommendations:
                recommendations_item = RemediationRecommendation.from_dict(recommendations_item_data)

                recommendations.append(recommendations_item)

        _discovered_at = d.pop("discovered_at", UNSET)
        discovered_at: datetime.datetime | Unset
        if isinstance(_discovered_at, Unset):
            discovered_at = UNSET
        else:
            discovered_at = isoparse(_discovered_at)

        _last_prioritized = d.pop("last_prioritized", UNSET)
        last_prioritized: datetime.datetime | Unset
        if isinstance(_last_prioritized, Unset):
            last_prioritized = UNSET
        else:
            last_prioritized = isoparse(_last_prioritized)

        org_id = d.pop("org_id", UNSET)

        prioritized_vuln = cls(
            finding_id=finding_id,
            title=title,
            asset_id=asset_id,
            asset_name=asset_name,
            id=id,
            cve_id=cve_id,
            epss_score=epss_score,
            reachability=reachability,
            reachability_factor=reachability_factor,
            business_impact=business_impact,
            compensating_controls=compensating_controls,
            composite_score=composite_score,
            risk_bucket=risk_bucket,
            sla_deadline=sla_deadline,
            sla_breached=sla_breached,
            days_open=days_open,
            assigned_team=assigned_team,
            group_id=group_id,
            recommendations=recommendations,
            discovered_at=discovered_at,
            last_prioritized=last_prioritized,
            org_id=org_id,
        )

        prioritized_vuln.additional_properties = d
        return prioritized_vuln

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
