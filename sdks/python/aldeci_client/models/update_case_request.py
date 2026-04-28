from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.update_case_request_metadata_type_0 import UpdateCaseRequestMetadataType0


T = TypeVar("T", bound="UpdateCaseRequest")


@_attrs_define
class UpdateCaseRequest:
    """
    Attributes:
        title (None | str | Unset):
        description (None | str | Unset):
        priority (None | str | Unset):
        assigned_to (None | str | Unset):
        assigned_team (None | str | Unset):
        sla_due (None | str | Unset):
        remediation_plan (None | str | Unset):
        playbook_id (None | str | Unset):
        autofix_pr_url (None | str | Unset):
        risk_score (float | None | Unset):
        tags (list[str] | None | Unset):
        metadata (None | Unset | UpdateCaseRequestMetadataType0):
    """

    title: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    priority: None | str | Unset = UNSET
    assigned_to: None | str | Unset = UNSET
    assigned_team: None | str | Unset = UNSET
    sla_due: None | str | Unset = UNSET
    remediation_plan: None | str | Unset = UNSET
    playbook_id: None | str | Unset = UNSET
    autofix_pr_url: None | str | Unset = UNSET
    risk_score: float | None | Unset = UNSET
    tags: list[str] | None | Unset = UNSET
    metadata: None | Unset | UpdateCaseRequestMetadataType0 = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.update_case_request_metadata_type_0 import UpdateCaseRequestMetadataType0

        title: None | str | Unset
        if isinstance(self.title, Unset):
            title = UNSET
        else:
            title = self.title

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        priority: None | str | Unset
        if isinstance(self.priority, Unset):
            priority = UNSET
        else:
            priority = self.priority

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

        remediation_plan: None | str | Unset
        if isinstance(self.remediation_plan, Unset):
            remediation_plan = UNSET
        else:
            remediation_plan = self.remediation_plan

        playbook_id: None | str | Unset
        if isinstance(self.playbook_id, Unset):
            playbook_id = UNSET
        else:
            playbook_id = self.playbook_id

        autofix_pr_url: None | str | Unset
        if isinstance(self.autofix_pr_url, Unset):
            autofix_pr_url = UNSET
        else:
            autofix_pr_url = self.autofix_pr_url

        risk_score: float | None | Unset
        if isinstance(self.risk_score, Unset):
            risk_score = UNSET
        else:
            risk_score = self.risk_score

        tags: list[str] | None | Unset
        if isinstance(self.tags, Unset):
            tags = UNSET
        elif isinstance(self.tags, list):
            tags = self.tags

        else:
            tags = self.tags

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, UpdateCaseRequestMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if title is not UNSET:
            field_dict["title"] = title
        if description is not UNSET:
            field_dict["description"] = description
        if priority is not UNSET:
            field_dict["priority"] = priority
        if assigned_to is not UNSET:
            field_dict["assigned_to"] = assigned_to
        if assigned_team is not UNSET:
            field_dict["assigned_team"] = assigned_team
        if sla_due is not UNSET:
            field_dict["sla_due"] = sla_due
        if remediation_plan is not UNSET:
            field_dict["remediation_plan"] = remediation_plan
        if playbook_id is not UNSET:
            field_dict["playbook_id"] = playbook_id
        if autofix_pr_url is not UNSET:
            field_dict["autofix_pr_url"] = autofix_pr_url
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if tags is not UNSET:
            field_dict["tags"] = tags
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.update_case_request_metadata_type_0 import UpdateCaseRequestMetadataType0

        d = dict(src_dict)

        def _parse_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        title = _parse_title(d.pop("title", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_priority(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        priority = _parse_priority(d.pop("priority", UNSET))

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

        def _parse_remediation_plan(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation_plan = _parse_remediation_plan(d.pop("remediation_plan", UNSET))

        def _parse_playbook_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        playbook_id = _parse_playbook_id(d.pop("playbook_id", UNSET))

        def _parse_autofix_pr_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        autofix_pr_url = _parse_autofix_pr_url(d.pop("autofix_pr_url", UNSET))

        def _parse_risk_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        risk_score = _parse_risk_score(d.pop("risk_score", UNSET))

        def _parse_tags(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                tags_type_0 = cast(list[str], data)

                return tags_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        tags = _parse_tags(d.pop("tags", UNSET))

        def _parse_metadata(data: object) -> None | Unset | UpdateCaseRequestMetadataType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = UpdateCaseRequestMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UpdateCaseRequestMetadataType0, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        update_case_request = cls(
            title=title,
            description=description,
            priority=priority,
            assigned_to=assigned_to,
            assigned_team=assigned_team,
            sla_due=sla_due,
            remediation_plan=remediation_plan,
            playbook_id=playbook_id,
            autofix_pr_url=autofix_pr_url,
            risk_score=risk_score,
            tags=tags,
            metadata=metadata,
        )

        update_case_request.additional_properties = d
        return update_case_request

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
