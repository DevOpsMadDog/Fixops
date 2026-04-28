from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="StartRunRequest")


@_attrs_define
class StartRunRequest:
    """
    Attributes:
        org_id (str): Organisation ID
        repo_ref (str): Repository reference (org/repo)
        ci_provider (str): github-actions|gitlab-ci|jenkins|circleci|azure-devops|argo|tekton|other
        run_id_external (str | Unset): CI provider's native run ID Default: ''.
        trigger (str | Unset): push|pull_request|schedule|manual|tag Default: ''.
        branch (str | Unset):  Default: ''.
        commit_sha (str | Unset): Git commit SHA Default: ''.
    """

    org_id: str
    repo_ref: str
    ci_provider: str
    run_id_external: str | Unset = ""
    trigger: str | Unset = ""
    branch: str | Unset = ""
    commit_sha: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        repo_ref = self.repo_ref

        ci_provider = self.ci_provider

        run_id_external = self.run_id_external

        trigger = self.trigger

        branch = self.branch

        commit_sha = self.commit_sha

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "repo_ref": repo_ref,
                "ci_provider": ci_provider,
            }
        )
        if run_id_external is not UNSET:
            field_dict["run_id_external"] = run_id_external
        if trigger is not UNSET:
            field_dict["trigger"] = trigger
        if branch is not UNSET:
            field_dict["branch"] = branch
        if commit_sha is not UNSET:
            field_dict["commit_sha"] = commit_sha

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        repo_ref = d.pop("repo_ref")

        ci_provider = d.pop("ci_provider")

        run_id_external = d.pop("run_id_external", UNSET)

        trigger = d.pop("trigger", UNSET)

        branch = d.pop("branch", UNSET)

        commit_sha = d.pop("commit_sha", UNSET)

        start_run_request = cls(
            org_id=org_id,
            repo_ref=repo_ref,
            ci_provider=ci_provider,
            run_id_external=run_id_external,
            trigger=trigger,
            branch=branch,
            commit_sha=commit_sha,
        )

        start_run_request.additional_properties = d
        return start_run_request

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
