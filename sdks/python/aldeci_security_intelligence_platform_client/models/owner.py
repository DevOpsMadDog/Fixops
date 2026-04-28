from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Owner")


@_attrs_define
class Owner:
    """A code owner — a person or team responsible for one or more file paths.

    Attributes:
        email (str): Unique identifier / contact email
        name (str): Human-readable display name
        team (str): Team or squad name
        repos (list[str] | Unset): Repos this owner is responsible for
        file_patterns (list[str] | Unset): Glob patterns for files this owner is responsible for
        created_at (str | Unset):
    """

    email: str
    name: str
    team: str
    repos: list[str] | Unset = UNSET
    file_patterns: list[str] | Unset = UNSET
    created_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        email = self.email

        name = self.name

        team = self.team

        repos: list[str] | Unset = UNSET
        if not isinstance(self.repos, Unset):
            repos = self.repos

        file_patterns: list[str] | Unset = UNSET
        if not isinstance(self.file_patterns, Unset):
            file_patterns = self.file_patterns

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "email": email,
                "name": name,
                "team": team,
            }
        )
        if repos is not UNSET:
            field_dict["repos"] = repos
        if file_patterns is not UNSET:
            field_dict["file_patterns"] = file_patterns
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        email = d.pop("email")

        name = d.pop("name")

        team = d.pop("team")

        repos = cast(list[str], d.pop("repos", UNSET))

        file_patterns = cast(list[str], d.pop("file_patterns", UNSET))

        created_at = d.pop("created_at", UNSET)

        owner = cls(
            email=email,
            name=name,
            team=team,
            repos=repos,
            file_patterns=file_patterns,
            created_at=created_at,
        )

        owner.additional_properties = d
        return owner

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
