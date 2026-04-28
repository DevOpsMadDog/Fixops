from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GitRepositoryRequest")


@_attrs_define
class GitRepositoryRequest:
    """Git repository configuration.

    Attributes:
        url (str): Repository URL
        branch (str | Unset): Branch to analyze Default: 'main'.
        commit (None | str | Unset): Specific commit to analyze
        auth_token (None | str | Unset): Authentication token
        auth_username (None | str | Unset): Username for authentication
        auth_password (None | str | Unset): Password for authentication
    """

    url: str
    branch: str | Unset = "main"
    commit: None | str | Unset = UNSET
    auth_token: None | str | Unset = UNSET
    auth_username: None | str | Unset = UNSET
    auth_password: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        url = self.url

        branch = self.branch

        commit: None | str | Unset
        if isinstance(self.commit, Unset):
            commit = UNSET
        else:
            commit = self.commit

        auth_token: None | str | Unset
        if isinstance(self.auth_token, Unset):
            auth_token = UNSET
        else:
            auth_token = self.auth_token

        auth_username: None | str | Unset
        if isinstance(self.auth_username, Unset):
            auth_username = UNSET
        else:
            auth_username = self.auth_username

        auth_password: None | str | Unset
        if isinstance(self.auth_password, Unset):
            auth_password = UNSET
        else:
            auth_password = self.auth_password

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "url": url,
            }
        )
        if branch is not UNSET:
            field_dict["branch"] = branch
        if commit is not UNSET:
            field_dict["commit"] = commit
        if auth_token is not UNSET:
            field_dict["auth_token"] = auth_token
        if auth_username is not UNSET:
            field_dict["auth_username"] = auth_username
        if auth_password is not UNSET:
            field_dict["auth_password"] = auth_password

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        url = d.pop("url")

        branch = d.pop("branch", UNSET)

        def _parse_commit(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        commit = _parse_commit(d.pop("commit", UNSET))

        def _parse_auth_token(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        auth_token = _parse_auth_token(d.pop("auth_token", UNSET))

        def _parse_auth_username(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        auth_username = _parse_auth_username(d.pop("auth_username", UNSET))

        def _parse_auth_password(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        auth_password = _parse_auth_password(d.pop("auth_password", UNSET))

        git_repository_request = cls(
            url=url,
            branch=branch,
            commit=commit,
            auth_token=auth_token,
            auth_username=auth_username,
            auth_password=auth_password,
        )

        git_repository_request.additional_properties = d
        return git_repository_request

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
