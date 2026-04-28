from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="JiraConfig")


@_attrs_define
class JiraConfig:
    """
    Attributes:
        base_url (str): Jira instance URL
        email (str): Jira user email
        api_token (str): Jira API token
        project_key (str): Jira project key
        issue_type (str | Unset): Default issue type Default: 'Bug'.
    """

    base_url: str
    email: str
    api_token: str
    project_key: str
    issue_type: str | Unset = "Bug"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        base_url = self.base_url

        email = self.email

        api_token = self.api_token

        project_key = self.project_key

        issue_type = self.issue_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "base_url": base_url,
                "email": email,
                "api_token": api_token,
                "project_key": project_key,
            }
        )
        if issue_type is not UNSET:
            field_dict["issue_type"] = issue_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        base_url = d.pop("base_url")

        email = d.pop("email")

        api_token = d.pop("api_token")

        project_key = d.pop("project_key")

        issue_type = d.pop("issue_type", UNSET)

        jira_config = cls(
            base_url=base_url,
            email=email,
            api_token=api_token,
            project_key=project_key,
            issue_type=issue_type,
        )

        jira_config.additional_properties = d
        return jira_config

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
