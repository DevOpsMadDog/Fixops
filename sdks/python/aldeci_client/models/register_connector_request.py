from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.connector_type import ConnectorType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.git_hub_config import GitHubConfig
    from ..models.jira_config import JiraConfig
    from ..models.slack_config import SlackConfig


T = TypeVar("T", bound="RegisterConnectorRequest")


@_attrs_define
class RegisterConnectorRequest:
    """
    Attributes:
        name (str): Unique connector name
        type_ (ConnectorType):
        jira (JiraConfig | None | Unset):
        github (GitHubConfig | None | Unset):
        slack (None | SlackConfig | Unset):
    """

    name: str
    type_: ConnectorType
    jira: JiraConfig | None | Unset = UNSET
    github: GitHubConfig | None | Unset = UNSET
    slack: None | SlackConfig | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.git_hub_config import GitHubConfig
        from ..models.jira_config import JiraConfig
        from ..models.slack_config import SlackConfig

        name = self.name

        type_ = self.type_.value

        jira: dict[str, Any] | None | Unset
        if isinstance(self.jira, Unset):
            jira = UNSET
        elif isinstance(self.jira, JiraConfig):
            jira = self.jira.to_dict()
        else:
            jira = self.jira

        github: dict[str, Any] | None | Unset
        if isinstance(self.github, Unset):
            github = UNSET
        elif isinstance(self.github, GitHubConfig):
            github = self.github.to_dict()
        else:
            github = self.github

        slack: dict[str, Any] | None | Unset
        if isinstance(self.slack, Unset):
            slack = UNSET
        elif isinstance(self.slack, SlackConfig):
            slack = self.slack.to_dict()
        else:
            slack = self.slack

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "type": type_,
            }
        )
        if jira is not UNSET:
            field_dict["jira"] = jira
        if github is not UNSET:
            field_dict["github"] = github
        if slack is not UNSET:
            field_dict["slack"] = slack

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.git_hub_config import GitHubConfig
        from ..models.jira_config import JiraConfig
        from ..models.slack_config import SlackConfig

        d = dict(src_dict)
        name = d.pop("name")

        type_ = ConnectorType(d.pop("type"))

        def _parse_jira(data: object) -> JiraConfig | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                jira_type_0 = JiraConfig.from_dict(data)

                return jira_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(JiraConfig | None | Unset, data)

        jira = _parse_jira(d.pop("jira", UNSET))

        def _parse_github(data: object) -> GitHubConfig | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                github_type_0 = GitHubConfig.from_dict(data)

                return github_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GitHubConfig | None | Unset, data)

        github = _parse_github(d.pop("github", UNSET))

        def _parse_slack(data: object) -> None | SlackConfig | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                slack_type_0 = SlackConfig.from_dict(data)

                return slack_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SlackConfig | Unset, data)

        slack = _parse_slack(d.pop("slack", UNSET))

        register_connector_request = cls(
            name=name,
            type_=type_,
            jira=jira,
            github=github,
            slack=slack,
        )

        register_connector_request.additional_properties = d
        return register_connector_request

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
