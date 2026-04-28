from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_case_request_metadata import CreateCaseRequestMetadata


T = TypeVar("T", bound="CreateCaseRequest")


@_attrs_define
class CreateCaseRequest:
    """
    Attributes:
        title (str):
        description (str | Unset):  Default: ''.
        org_id (str | Unset):  Default: ''.
        priority (str | Unset): critical|high|medium|low|info Default: 'medium'.
        root_cve (None | str | Unset):
        root_cwe (None | str | Unset):
        root_component (None | str | Unset):
        affected_assets (list[str] | Unset):
        cluster_ids (list[str] | Unset):
        finding_count (int | Unset):  Default: 0.
        risk_score (float | Unset):  Default: 0.0.
        epss_score (float | None | Unset):
        in_kev (bool | Unset):  Default: False.
        blast_radius (int | Unset):  Default: 0.
        assigned_to (None | str | Unset):
        assigned_team (None | str | Unset):
        sla_due (None | str | Unset):
        tags (list[str] | Unset):
        metadata (CreateCaseRequestMetadata | Unset):
    """

    title: str
    description: str | Unset = ""
    org_id: str | Unset = ""
    priority: str | Unset = "medium"
    root_cve: None | str | Unset = UNSET
    root_cwe: None | str | Unset = UNSET
    root_component: None | str | Unset = UNSET
    affected_assets: list[str] | Unset = UNSET
    cluster_ids: list[str] | Unset = UNSET
    finding_count: int | Unset = 0
    risk_score: float | Unset = 0.0
    epss_score: float | None | Unset = UNSET
    in_kev: bool | Unset = False
    blast_radius: int | Unset = 0
    assigned_to: None | str | Unset = UNSET
    assigned_team: None | str | Unset = UNSET
    sla_due: None | str | Unset = UNSET
    tags: list[str] | Unset = UNSET
    metadata: CreateCaseRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        description = self.description

        org_id = self.org_id

        priority = self.priority

        root_cve: None | str | Unset
        if isinstance(self.root_cve, Unset):
            root_cve = UNSET
        else:
            root_cve = self.root_cve

        root_cwe: None | str | Unset
        if isinstance(self.root_cwe, Unset):
            root_cwe = UNSET
        else:
            root_cwe = self.root_cwe

        root_component: None | str | Unset
        if isinstance(self.root_component, Unset):
            root_component = UNSET
        else:
            root_component = self.root_component

        affected_assets: list[str] | Unset = UNSET
        if not isinstance(self.affected_assets, Unset):
            affected_assets = self.affected_assets

        cluster_ids: list[str] | Unset = UNSET
        if not isinstance(self.cluster_ids, Unset):
            cluster_ids = self.cluster_ids

        finding_count = self.finding_count

        risk_score = self.risk_score

        epss_score: float | None | Unset
        if isinstance(self.epss_score, Unset):
            epss_score = UNSET
        else:
            epss_score = self.epss_score

        in_kev = self.in_kev

        blast_radius = self.blast_radius

        assigned_to: None | str | Unset
        if isinstance(self.assigned_to, Unset):
            assigned_to = UNSET
        else:
            assigned_to = self.assigned_to

        assigned_team: None | str | Unset
        if isinstance(self.assigned_team, Unset):
            assigned_team = UNSET
        else:
            assigned_team = self.assigned_team

        sla_due: None | str | Unset
        if isinstance(self.sla_due, Unset):
            sla_due = UNSET
        else:
            sla_due = self.sla_due

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if priority is not UNSET:
            field_dict["priority"] = priority
        if root_cve is not UNSET:
            field_dict["root_cve"] = root_cve
        if root_cwe is not UNSET:
            field_dict["root_cwe"] = root_cwe
        if root_component is not UNSET:
            field_dict["root_component"] = root_component
        if affected_assets is not UNSET:
            field_dict["affected_assets"] = affected_assets
        if cluster_ids is not UNSET:
            field_dict["cluster_ids"] = cluster_ids
        if finding_count is not UNSET:
            field_dict["finding_count"] = finding_count
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if in_kev is not UNSET:
            field_dict["in_kev"] = in_kev
        if blast_radius is not UNSET:
            field_dict["blast_radius"] = blast_radius
        if assigned_to is not UNSET:
            field_dict["assigned_to"] = assigned_to
        if assigned_team is not UNSET:
            field_dict["assigned_team"] = assigned_team
        if sla_due is not UNSET:
            field_dict["sla_due"] = sla_due
        if tags is not UNSET:
            field_dict["tags"] = tags
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_case_request_metadata import CreateCaseRequestMetadata

        d = dict(src_dict)
        title = d.pop("title")

        description = d.pop("description", UNSET)

        org_id = d.pop("org_id", UNSET)

        priority = d.pop("priority", UNSET)

        def _parse_root_cve(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        root_cve = _parse_root_cve(d.pop("root_cve", UNSET))

        def _parse_root_cwe(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        root_cwe = _parse_root_cwe(d.pop("root_cwe", UNSET))

        def _parse_root_component(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        root_component = _parse_root_component(d.pop("root_component", UNSET))

        affected_assets = cast(list[str], d.pop("affected_assets", UNSET))

        cluster_ids = cast(list[str], d.pop("cluster_ids", UNSET))

        finding_count = d.pop("finding_count", UNSET)

        risk_score = d.pop("risk_score", UNSET)

        def _parse_epss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        epss_score = _parse_epss_score(d.pop("epss_score", UNSET))

        in_kev = d.pop("in_kev", UNSET)

        blast_radius = d.pop("blast_radius", UNSET)

        def _parse_assigned_to(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assigned_to = _parse_assigned_to(d.pop("assigned_to", UNSET))

        def _parse_assigned_team(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assigned_team = _parse_assigned_team(d.pop("assigned_team", UNSET))

        def _parse_sla_due(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sla_due = _parse_sla_due(d.pop("sla_due", UNSET))

        tags = cast(list[str], d.pop("tags", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: CreateCaseRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = CreateCaseRequestMetadata.from_dict(_metadata)

        create_case_request = cls(
            title=title,
            description=description,
            org_id=org_id,
            priority=priority,
            root_cve=root_cve,
            root_cwe=root_cwe,
            root_component=root_component,
            affected_assets=affected_assets,
            cluster_ids=cluster_ids,
            finding_count=finding_count,
            risk_score=risk_score,
            epss_score=epss_score,
            in_kev=in_kev,
            blast_radius=blast_radius,
            assigned_to=assigned_to,
            assigned_team=assigned_team,
            sla_due=sla_due,
            tags=tags,
            metadata=metadata,
        )

        create_case_request.additional_properties = d
        return create_case_request

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
