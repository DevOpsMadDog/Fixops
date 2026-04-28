from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

if TYPE_CHECKING:
    from ..models.comment_response import CommentResponse
    from ..models.finding_detail_response_council_verdict_type_0 import FindingDetailResponseCouncilVerdictType0
    from ..models.finding_detail_response_pipeline_history_item import FindingDetailResponsePipelineHistoryItem
    from ..models.finding_detail_response_playbook_runs_item import FindingDetailResponsePlaybookRunsItem
    from ..models.timeline_event import TimelineEvent


T = TypeVar("T", bound="FindingDetailResponse")


@_attrs_define
class FindingDetailResponse:
    """Complete finding detail.

    Attributes:
        id (str):
        title (str):
        description (None | str):
        severity (str):
        status (str):
        connector (str):
        asset_id (None | str):
        cve_id (None | str):
        risk_score (float):
        created_at (datetime.datetime):
        updated_at (datetime.datetime):
        last_seen (datetime.datetime):
        assigned_to (None | str):
        assigned_team (None | str):
        pipeline_history (list[FindingDetailResponsePipelineHistoryItem]):
        related_findings (list[str]):
        council_verdict (FindingDetailResponseCouncilVerdictType0 | None):
        playbook_runs (list[FindingDetailResponsePlaybookRunsItem]):
        comments (list[CommentResponse]):
        audit_trail (list[TimelineEvent]):
    """

    id: str
    title: str
    description: None | str
    severity: str
    status: str
    connector: str
    asset_id: None | str
    cve_id: None | str
    risk_score: float
    created_at: datetime.datetime
    updated_at: datetime.datetime
    last_seen: datetime.datetime
    assigned_to: None | str
    assigned_team: None | str
    pipeline_history: list[FindingDetailResponsePipelineHistoryItem]
    related_findings: list[str]
    council_verdict: FindingDetailResponseCouncilVerdictType0 | None
    playbook_runs: list[FindingDetailResponsePlaybookRunsItem]
    comments: list[CommentResponse]
    audit_trail: list[TimelineEvent]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.finding_detail_response_council_verdict_type_0 import FindingDetailResponseCouncilVerdictType0

        id = self.id

        title = self.title

        description: None | str
        description = self.description

        severity = self.severity

        status = self.status

        connector = self.connector

        asset_id: None | str
        asset_id = self.asset_id

        cve_id: None | str
        cve_id = self.cve_id

        risk_score = self.risk_score

        created_at = self.created_at.isoformat()

        updated_at = self.updated_at.isoformat()

        last_seen = self.last_seen.isoformat()

        assigned_to: None | str
        assigned_to = self.assigned_to

        assigned_team: None | str
        assigned_team = self.assigned_team

        pipeline_history = []
        for pipeline_history_item_data in self.pipeline_history:
            pipeline_history_item = pipeline_history_item_data.to_dict()
            pipeline_history.append(pipeline_history_item)

        related_findings = self.related_findings

        council_verdict: dict[str, Any] | None
        if isinstance(self.council_verdict, FindingDetailResponseCouncilVerdictType0):
            council_verdict = self.council_verdict.to_dict()
        else:
            council_verdict = self.council_verdict

        playbook_runs = []
        for playbook_runs_item_data in self.playbook_runs:
            playbook_runs_item = playbook_runs_item_data.to_dict()
            playbook_runs.append(playbook_runs_item)

        comments = []
        for comments_item_data in self.comments:
            comments_item = comments_item_data.to_dict()
            comments.append(comments_item)

        audit_trail = []
        for audit_trail_item_data in self.audit_trail:
            audit_trail_item = audit_trail_item_data.to_dict()
            audit_trail.append(audit_trail_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "title": title,
                "description": description,
                "severity": severity,
                "status": status,
                "connector": connector,
                "asset_id": asset_id,
                "cve_id": cve_id,
                "risk_score": risk_score,
                "created_at": created_at,
                "updated_at": updated_at,
                "last_seen": last_seen,
                "assigned_to": assigned_to,
                "assigned_team": assigned_team,
                "pipeline_history": pipeline_history,
                "related_findings": related_findings,
                "council_verdict": council_verdict,
                "playbook_runs": playbook_runs,
                "comments": comments,
                "audit_trail": audit_trail,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.comment_response import CommentResponse
        from ..models.finding_detail_response_council_verdict_type_0 import FindingDetailResponseCouncilVerdictType0
        from ..models.finding_detail_response_pipeline_history_item import FindingDetailResponsePipelineHistoryItem
        from ..models.finding_detail_response_playbook_runs_item import FindingDetailResponsePlaybookRunsItem
        from ..models.timeline_event import TimelineEvent

        d = dict(src_dict)
        id = d.pop("id")

        title = d.pop("title")

        def _parse_description(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        description = _parse_description(d.pop("description"))

        severity = d.pop("severity")

        status = d.pop("status")

        connector = d.pop("connector")

        def _parse_asset_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        asset_id = _parse_asset_id(d.pop("asset_id"))

        def _parse_cve_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        cve_id = _parse_cve_id(d.pop("cve_id"))

        risk_score = d.pop("risk_score")

        created_at = isoparse(d.pop("created_at"))

        updated_at = isoparse(d.pop("updated_at"))

        last_seen = isoparse(d.pop("last_seen"))

        def _parse_assigned_to(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        assigned_to = _parse_assigned_to(d.pop("assigned_to"))

        def _parse_assigned_team(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        assigned_team = _parse_assigned_team(d.pop("assigned_team"))

        pipeline_history = []
        _pipeline_history = d.pop("pipeline_history")
        for pipeline_history_item_data in _pipeline_history:
            pipeline_history_item = FindingDetailResponsePipelineHistoryItem.from_dict(pipeline_history_item_data)

            pipeline_history.append(pipeline_history_item)

        related_findings = cast(list[str], d.pop("related_findings"))

        def _parse_council_verdict(data: object) -> FindingDetailResponseCouncilVerdictType0 | None:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                council_verdict_type_0 = FindingDetailResponseCouncilVerdictType0.from_dict(data)

                return council_verdict_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(FindingDetailResponseCouncilVerdictType0 | None, data)

        council_verdict = _parse_council_verdict(d.pop("council_verdict"))

        playbook_runs = []
        _playbook_runs = d.pop("playbook_runs")
        for playbook_runs_item_data in _playbook_runs:
            playbook_runs_item = FindingDetailResponsePlaybookRunsItem.from_dict(playbook_runs_item_data)

            playbook_runs.append(playbook_runs_item)

        comments = []
        _comments = d.pop("comments")
        for comments_item_data in _comments:
            comments_item = CommentResponse.from_dict(comments_item_data)

            comments.append(comments_item)

        audit_trail = []
        _audit_trail = d.pop("audit_trail")
        for audit_trail_item_data in _audit_trail:
            audit_trail_item = TimelineEvent.from_dict(audit_trail_item_data)

            audit_trail.append(audit_trail_item)

        finding_detail_response = cls(
            id=id,
            title=title,
            description=description,
            severity=severity,
            status=status,
            connector=connector,
            asset_id=asset_id,
            cve_id=cve_id,
            risk_score=risk_score,
            created_at=created_at,
            updated_at=updated_at,
            last_seen=last_seen,
            assigned_to=assigned_to,
            assigned_team=assigned_team,
            pipeline_history=pipeline_history,
            related_findings=related_findings,
            council_verdict=council_verdict,
            playbook_runs=playbook_runs,
            comments=comments,
            audit_trail=audit_trail,
        )

        finding_detail_response.additional_properties = d
        return finding_detail_response

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
