from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterProjectRequest")


@_attrs_define
class RegisterProjectRequest:
    """
    Attributes:
        name (str): Project name
        language (str | Unset): Primary language: python, java, js, go, rust Default: 'python'.
        repo_url (str | Unset): Source repository URL Default: ''.
    """

    name: str
    language: str | Unset = "python"
    repo_url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        language = self.language

        repo_url = self.repo_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if language is not UNSET:
            field_dict["language"] = language
        if repo_url is not UNSET:
            field_dict["repo_url"] = repo_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        language = d.pop("language", UNSET)

        repo_url = d.pop("repo_url", UNSET)

        register_project_request = cls(
            name=name,
            language=language,
            repo_url=repo_url,
        )

        register_project_request.additional_properties = d
        return register_project_request

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
