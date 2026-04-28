from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AnalyzeRepoRequest")


@_attrs_define
class AnalyzeRepoRequest:
    """
    Attributes:
        repo_ref (str):
        root_path (str):
        commit_sha (str | Unset):  Default: ''.
        org_id (str | Unset):  Default: 'default'.
    """

    repo_ref: str
    root_path: str
    commit_sha: str | Unset = ""
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo_ref = self.repo_ref

        root_path = self.root_path

        commit_sha = self.commit_sha

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_ref": repo_ref,
                "root_path": root_path,
            }
        )
        if commit_sha is not UNSET:
            field_dict["commit_sha"] = commit_sha
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo_ref = d.pop("repo_ref")

        root_path = d.pop("root_path")

        commit_sha = d.pop("commit_sha", UNSET)

        org_id = d.pop("org_id", UNSET)

        analyze_repo_request = cls(
            repo_ref=repo_ref,
            root_path=root_path,
            commit_sha=commit_sha,
            org_id=org_id,
        )

        analyze_repo_request.additional_properties = d
        return analyze_repo_request

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
