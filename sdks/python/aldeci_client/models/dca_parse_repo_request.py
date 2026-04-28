from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DCAParseRepoRequest")


@_attrs_define
class DCAParseRepoRequest:
    """
    Attributes:
        repo (str):
        revision (str | Unset):  Default: 'HEAD'.
        languages (list[str] | Unset):
        include_tests (bool | Unset):  Default: False.
    """

    repo: str
    revision: str | Unset = "HEAD"
    languages: list[str] | Unset = UNSET
    include_tests: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo = self.repo

        revision = self.revision

        languages: list[str] | Unset = UNSET
        if not isinstance(self.languages, Unset):
            languages = self.languages

        include_tests = self.include_tests

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo": repo,
            }
        )
        if revision is not UNSET:
            field_dict["revision"] = revision
        if languages is not UNSET:
            field_dict["languages"] = languages
        if include_tests is not UNSET:
            field_dict["include_tests"] = include_tests

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo = d.pop("repo")

        revision = d.pop("revision", UNSET)

        languages = cast(list[str], d.pop("languages", UNSET))

        include_tests = d.pop("include_tests", UNSET)

        dca_parse_repo_request = cls(
            repo=repo,
            revision=revision,
            languages=languages,
            include_tests=include_tests,
        )

        dca_parse_repo_request.additional_properties = d
        return dca_parse_repo_request

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
