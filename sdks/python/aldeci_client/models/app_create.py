from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AppCreate")


@_attrs_define
class AppCreate:
    """
    Attributes:
        name (str):
        app_type (str | Unset):  Default: 'web'.
        language (str | Unset):  Default: 'other'.
        repo_url (str | Unset):  Default: ''.
        owner_team (str | Unset):  Default: ''.
        criticality (str | Unset):  Default: 'medium'.
        security_score (float | Unset):  Default: 0.0.
        status (str | Unset):  Default: 'active'.
    """

    name: str
    app_type: str | Unset = "web"
    language: str | Unset = "other"
    repo_url: str | Unset = ""
    owner_team: str | Unset = ""
    criticality: str | Unset = "medium"
    security_score: float | Unset = 0.0
    status: str | Unset = "active"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        app_type = self.app_type

        language = self.language

        repo_url = self.repo_url

        owner_team = self.owner_team

        criticality = self.criticality

        security_score = self.security_score

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if app_type is not UNSET:
            field_dict["app_type"] = app_type
        if language is not UNSET:
            field_dict["language"] = language
        if repo_url is not UNSET:
            field_dict["repo_url"] = repo_url
        if owner_team is not UNSET:
            field_dict["owner_team"] = owner_team
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if security_score is not UNSET:
            field_dict["security_score"] = security_score
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        app_type = d.pop("app_type", UNSET)

        language = d.pop("language", UNSET)

        repo_url = d.pop("repo_url", UNSET)

        owner_team = d.pop("owner_team", UNSET)

        criticality = d.pop("criticality", UNSET)

        security_score = d.pop("security_score", UNSET)

        status = d.pop("status", UNSET)

        app_create = cls(
            name=name,
            app_type=app_type,
            language=language,
            repo_url=repo_url,
            owner_team=owner_team,
            criticality=criticality,
            security_score=security_score,
            status=status,
        )

        app_create.additional_properties = d
        return app_create

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
