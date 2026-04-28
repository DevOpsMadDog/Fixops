from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.configure_request_finding_to_jira_transition_type_0 import (
        ConfigureRequestFindingToJiraTransitionType0,
    )
    from ..models.configure_request_jira_to_finding_status_type_0 import ConfigureRequestJiraToFindingStatusType0
    from ..models.configure_request_severity_to_priority_type_0 import ConfigureRequestSeverityToPriorityType0
    from ..models.field_mapping_item import FieldMappingItem


T = TypeVar("T", bound="ConfigureRequest")


@_attrs_define
class ConfigureRequest:
    """Configure the Jira sync engine.

    Attributes:
        jira_url (str): Jira base URL, e.g. https://example.atlassian.net
        user_email (str): Jira user email for API auth
        api_token (str): Jira API token or PAT
        project_key (str): Jira project key, e.g. SEC
        default_issue_type (str | Unset): Default Jira issue type Default: 'Bug'.
        sync_direction (str | Unset): bidirectional | finding_to_jira | jira_to_finding Default: 'bidirectional'.
        conflict_resolution (str | Unset): newest_wins | jira_wins | finding_wins | manual Default: 'newest_wins'.
        labels (list[str] | Unset):
        component_name (None | str | Unset): Jira component name to assign
        webhook_secret (None | str | Unset): Secret for validating Jira webhook calls
        field_mappings (list[FieldMappingItem] | Unset):
        jira_to_finding_status (ConfigureRequestJiraToFindingStatusType0 | None | Unset): Override Jira status → finding
            status mapping
        finding_to_jira_transition (ConfigureRequestFindingToJiraTransitionType0 | None | Unset): Override finding
            status → Jira transition name mapping
        severity_to_priority (ConfigureRequestSeverityToPriorityType0 | None | Unset): Override severity → Jira priority
            mapping
    """

    jira_url: str
    user_email: str
    api_token: str
    project_key: str
    default_issue_type: str | Unset = "Bug"
    sync_direction: str | Unset = "bidirectional"
    conflict_resolution: str | Unset = "newest_wins"
    labels: list[str] | Unset = UNSET
    component_name: None | str | Unset = UNSET
    webhook_secret: None | str | Unset = UNSET
    field_mappings: list[FieldMappingItem] | Unset = UNSET
    jira_to_finding_status: ConfigureRequestJiraToFindingStatusType0 | None | Unset = UNSET
    finding_to_jira_transition: ConfigureRequestFindingToJiraTransitionType0 | None | Unset = UNSET
    severity_to_priority: ConfigureRequestSeverityToPriorityType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.configure_request_finding_to_jira_transition_type_0 import (
            ConfigureRequestFindingToJiraTransitionType0,
        )
        from ..models.configure_request_jira_to_finding_status_type_0 import ConfigureRequestJiraToFindingStatusType0
        from ..models.configure_request_severity_to_priority_type_0 import ConfigureRequestSeverityToPriorityType0

        jira_url = self.jira_url

        user_email = self.user_email

        api_token = self.api_token

        project_key = self.project_key

        default_issue_type = self.default_issue_type

        sync_direction = self.sync_direction

        conflict_resolution = self.conflict_resolution

        labels: list[str] | Unset = UNSET
        if not isinstance(self.labels, Unset):
            labels = self.labels

        component_name: None | str | Unset
        if isinstance(self.component_name, Unset):
            component_name = UNSET
        else:
            component_name = self.component_name

        webhook_secret: None | str | Unset
        if isinstance(self.webhook_secret, Unset):
            webhook_secret = UNSET
        else:
            webhook_secret = self.webhook_secret

        field_mappings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.field_mappings, Unset):
            field_mappings = []
            for field_mappings_item_data in self.field_mappings:
                field_mappings_item = field_mappings_item_data.to_dict()
                field_mappings.append(field_mappings_item)

        jira_to_finding_status: dict[str, Any] | None | Unset
        if isinstance(self.jira_to_finding_status, Unset):
            jira_to_finding_status = UNSET
        elif isinstance(self.jira_to_finding_status, ConfigureRequestJiraToFindingStatusType0):
            jira_to_finding_status = self.jira_to_finding_status.to_dict()
        else:
            jira_to_finding_status = self.jira_to_finding_status

        finding_to_jira_transition: dict[str, Any] | None | Unset
        if isinstance(self.finding_to_jira_transition, Unset):
            finding_to_jira_transition = UNSET
        elif isinstance(self.finding_to_jira_transition, ConfigureRequestFindingToJiraTransitionType0):
            finding_to_jira_transition = self.finding_to_jira_transition.to_dict()
        else:
            finding_to_jira_transition = self.finding_to_jira_transition

        severity_to_priority: dict[str, Any] | None | Unset
        if isinstance(self.severity_to_priority, Unset):
            severity_to_priority = UNSET
        elif isinstance(self.severity_to_priority, ConfigureRequestSeverityToPriorityType0):
            severity_to_priority = self.severity_to_priority.to_dict()
        else:
            severity_to_priority = self.severity_to_priority

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "jira_url": jira_url,
                "user_email": user_email,
                "api_token": api_token,
                "project_key": project_key,
            }
        )
        if default_issue_type is not UNSET:
            field_dict["default_issue_type"] = default_issue_type
        if sync_direction is not UNSET:
            field_dict["sync_direction"] = sync_direction
        if conflict_resolution is not UNSET:
            field_dict["conflict_resolution"] = conflict_resolution
        if labels is not UNSET:
            field_dict["labels"] = labels
        if component_name is not UNSET:
            field_dict["component_name"] = component_name
        if webhook_secret is not UNSET:
            field_dict["webhook_secret"] = webhook_secret
        if field_mappings is not UNSET:
            field_dict["field_mappings"] = field_mappings
        if jira_to_finding_status is not UNSET:
            field_dict["jira_to_finding_status"] = jira_to_finding_status
        if finding_to_jira_transition is not UNSET:
            field_dict["finding_to_jira_transition"] = finding_to_jira_transition
        if severity_to_priority is not UNSET:
            field_dict["severity_to_priority"] = severity_to_priority

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.configure_request_finding_to_jira_transition_type_0 import (
            ConfigureRequestFindingToJiraTransitionType0,
        )
        from ..models.configure_request_jira_to_finding_status_type_0 import ConfigureRequestJiraToFindingStatusType0
        from ..models.configure_request_severity_to_priority_type_0 import ConfigureRequestSeverityToPriorityType0
        from ..models.field_mapping_item import FieldMappingItem

        d = dict(src_dict)
        jira_url = d.pop("jira_url")

        user_email = d.pop("user_email")

        api_token = d.pop("api_token")

        project_key = d.pop("project_key")

        default_issue_type = d.pop("default_issue_type", UNSET)

        sync_direction = d.pop("sync_direction", UNSET)

        conflict_resolution = d.pop("conflict_resolution", UNSET)

        labels = cast(list[str], d.pop("labels", UNSET))

        def _parse_component_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        component_name = _parse_component_name(d.pop("component_name", UNSET))

        def _parse_webhook_secret(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        webhook_secret = _parse_webhook_secret(d.pop("webhook_secret", UNSET))

        _field_mappings = d.pop("field_mappings", UNSET)
        field_mappings: list[FieldMappingItem] | Unset = UNSET
        if _field_mappings is not UNSET:
            field_mappings = []
            for field_mappings_item_data in _field_mappings:
                field_mappings_item = FieldMappingItem.from_dict(field_mappings_item_data)

                field_mappings.append(field_mappings_item)

        def _parse_jira_to_finding_status(data: object) -> ConfigureRequestJiraToFindingStatusType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                jira_to_finding_status_type_0 = ConfigureRequestJiraToFindingStatusType0.from_dict(data)

                return jira_to_finding_status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ConfigureRequestJiraToFindingStatusType0 | None | Unset, data)

        jira_to_finding_status = _parse_jira_to_finding_status(d.pop("jira_to_finding_status", UNSET))

        def _parse_finding_to_jira_transition(
            data: object,
        ) -> ConfigureRequestFindingToJiraTransitionType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                finding_to_jira_transition_type_0 = ConfigureRequestFindingToJiraTransitionType0.from_dict(data)

                return finding_to_jira_transition_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ConfigureRequestFindingToJiraTransitionType0 | None | Unset, data)

        finding_to_jira_transition = _parse_finding_to_jira_transition(d.pop("finding_to_jira_transition", UNSET))

        def _parse_severity_to_priority(data: object) -> ConfigureRequestSeverityToPriorityType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                severity_to_priority_type_0 = ConfigureRequestSeverityToPriorityType0.from_dict(data)

                return severity_to_priority_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ConfigureRequestSeverityToPriorityType0 | None | Unset, data)

        severity_to_priority = _parse_severity_to_priority(d.pop("severity_to_priority", UNSET))

        configure_request = cls(
            jira_url=jira_url,
            user_email=user_email,
            api_token=api_token,
            project_key=project_key,
            default_issue_type=default_issue_type,
            sync_direction=sync_direction,
            conflict_resolution=conflict_resolution,
            labels=labels,
            component_name=component_name,
            webhook_secret=webhook_secret,
            field_mappings=field_mappings,
            jira_to_finding_status=jira_to_finding_status,
            finding_to_jira_transition=finding_to_jira_transition,
            severity_to_priority=severity_to_priority,
        )

        configure_request.additional_properties = d
        return configure_request

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
