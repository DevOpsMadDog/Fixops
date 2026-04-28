from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CommitAnalyzeRequest")


@_attrs_define
class CommitAnalyzeRequest:
    """Request body for manual commit analysis.

    Attributes:
        commit_sha (str): Commit SHA to analyze
        repository (str | Unset): Repository full name (owner/repo) Default: ''.
        branch (str | Unset): Branch name Default: 'main'.
        changed_files (list[str] | Unset): List of changed file paths (relative to repo root)
    """

    commit_sha: str
    repository: str | Unset = ""
    branch: str | Unset = "main"
    changed_files: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        commit_sha = self.commit_sha

        repository = self.repository

        branch = self.branch

        changed_files: list[str] | Unset = UNSET
        if not isinstance(self.changed_files, Unset):
            changed_files = self.changed_files

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "commit_sha": commit_sha,
            }
        )
        if repository is not UNSET:
            field_dict["repository"] = repository
        if branch is not UNSET:
            field_dict["branch"] = branch
        if changed_files is not UNSET:
            field_dict["changed_files"] = changed_files

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        commit_sha = d.pop("commit_sha")

        repository = d.pop("repository", UNSET)

        branch = d.pop("branch", UNSET)

        changed_files = cast(list[str], d.pop("changed_files", UNSET))

        commit_analyze_request = cls(
            commit_sha=commit_sha,
            repository=repository,
            branch=branch,
            changed_files=changed_files,
        )

        commit_analyze_request.additional_properties = d
        return commit_analyze_request

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
