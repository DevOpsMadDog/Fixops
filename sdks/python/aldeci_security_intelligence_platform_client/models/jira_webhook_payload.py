from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.jira_webhook_payload_changelog_type_0 import JiraWebhookPayloadChangelogType0
    from ..models.jira_webhook_payload_issue_type_0 import JiraWebhookPayloadIssueType0
    from ..models.jira_webhook_payload_user_type_0 import JiraWebhookPayloadUserType0


T = TypeVar("T", bound="JiraWebhookPayload")


@_attrs_define
class JiraWebhookPayload:
    """
    Attributes:
        webhook_event (str):
        issue (JiraWebhookPayloadIssueType0 | None | Unset):
        changelog (JiraWebhookPayloadChangelogType0 | None | Unset):
        user (JiraWebhookPayloadUserType0 | None | Unset):
    """

    webhook_event: str
    issue: JiraWebhookPayloadIssueType0 | None | Unset = UNSET
    changelog: JiraWebhookPayloadChangelogType0 | None | Unset = UNSET
    user: JiraWebhookPayloadUserType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.jira_webhook_payload_changelog_type_0 import JiraWebhookPayloadChangelogType0
        from ..models.jira_webhook_payload_issue_type_0 import JiraWebhookPayloadIssueType0
        from ..models.jira_webhook_payload_user_type_0 import JiraWebhookPayloadUserType0

        webhook_event = self.webhook_event

        issue: dict[str, Any] | None | Unset
        if isinstance(self.issue, Unset):
            issue = UNSET
        elif isinstance(self.issue, JiraWebhookPayloadIssueType0):
            issue = self.issue.to_dict()
        else:
            issue = self.issue

        changelog: dict[str, Any] | None | Unset
        if isinstance(self.changelog, Unset):
            changelog = UNSET
        elif isinstance(self.changelog, JiraWebhookPayloadChangelogType0):
            changelog = self.changelog.to_dict()
        else:
            changelog = self.changelog

        user: dict[str, Any] | None | Unset
        if isinstance(self.user, Unset):
            user = UNSET
        elif isinstance(self.user, JiraWebhookPayloadUserType0):
            user = self.user.to_dict()
        else:
            user = self.user

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "webhookEvent": webhook_event,
            }
        )
        if issue is not UNSET:
            field_dict["issue"] = issue
        if changelog is not UNSET:
            field_dict["changelog"] = changelog
        if user is not UNSET:
            field_dict["user"] = user

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.jira_webhook_payload_changelog_type_0 import JiraWebhookPayloadChangelogType0
        from ..models.jira_webhook_payload_issue_type_0 import JiraWebhookPayloadIssueType0
        from ..models.jira_webhook_payload_user_type_0 import JiraWebhookPayloadUserType0

        d = dict(src_dict)
        webhook_event = d.pop("webhookEvent")

        def _parse_issue(data: object) -> JiraWebhookPayloadIssueType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                issue_type_0 = JiraWebhookPayloadIssueType0.from_dict(data)

                return issue_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(JiraWebhookPayloadIssueType0 | None | Unset, data)

        issue = _parse_issue(d.pop("issue", UNSET))

        def _parse_changelog(data: object) -> JiraWebhookPayloadChangelogType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                changelog_type_0 = JiraWebhookPayloadChangelogType0.from_dict(data)

                return changelog_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(JiraWebhookPayloadChangelogType0 | None | Unset, data)

        changelog = _parse_changelog(d.pop("changelog", UNSET))

        def _parse_user(data: object) -> JiraWebhookPayloadUserType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                user_type_0 = JiraWebhookPayloadUserType0.from_dict(data)

                return user_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(JiraWebhookPayloadUserType0 | None | Unset, data)

        user = _parse_user(d.pop("user", UNSET))

        jira_webhook_payload = cls(
            webhook_event=webhook_event,
            issue=issue,
            changelog=changelog,
            user=user,
        )

        jira_webhook_payload.additional_properties = d
        return jira_webhook_payload

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
