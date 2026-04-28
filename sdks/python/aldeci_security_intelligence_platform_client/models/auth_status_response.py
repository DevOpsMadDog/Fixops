from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AuthStatusResponse")


@_attrs_define
class AuthStatusResponse:
    """
    Attributes:
        available (bool):
        authenticated (bool):
        gh_bin (None | str | Unset):
        username (None | str | Unset):
        repo (None | str | Unset):
        error (None | str | Unset):
    """

    available: bool
    authenticated: bool
    gh_bin: None | str | Unset = UNSET
    username: None | str | Unset = UNSET
    repo: None | str | Unset = UNSET
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        available = self.available

        authenticated = self.authenticated

        gh_bin: None | str | Unset
        if isinstance(self.gh_bin, Unset):
            gh_bin = UNSET
        else:
            gh_bin = self.gh_bin

        username: None | str | Unset
        if isinstance(self.username, Unset):
            username = UNSET
        else:
            username = self.username

        repo: None | str | Unset
        if isinstance(self.repo, Unset):
            repo = UNSET
        else:
            repo = self.repo

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "available": available,
                "authenticated": authenticated,
            }
        )
        if gh_bin is not UNSET:
            field_dict["gh_bin"] = gh_bin
        if username is not UNSET:
            field_dict["username"] = username
        if repo is not UNSET:
            field_dict["repo"] = repo
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        available = d.pop("available")

        authenticated = d.pop("authenticated")

        def _parse_gh_bin(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        gh_bin = _parse_gh_bin(d.pop("gh_bin", UNSET))

        def _parse_username(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        username = _parse_username(d.pop("username", UNSET))

        def _parse_repo(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        repo = _parse_repo(d.pop("repo", UNSET))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        auth_status_response = cls(
            available=available,
            authenticated=authenticated,
            gh_bin=gh_bin,
            username=username,
            repo=repo,
            error=error,
        )

        auth_status_response.additional_properties = d
        return auth_status_response

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
