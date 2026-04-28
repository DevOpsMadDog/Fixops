from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PipelineCreate")


@_attrs_define
class PipelineCreate:
    """
    Attributes:
        name (str):
        repo_url (str | Unset):  Default: ''.
        branch (str | Unset):  Default: 'main'.
        ci_platform (str | Unset):  Default: 'github_actions'.
        security_gates_enabled (int | Unset):  Default: 1.
        sast_enabled (int | Unset):  Default: 1.
        dast_enabled (int | Unset):  Default: 0.
        sca_enabled (int | Unset):  Default: 1.
        secret_scan_enabled (int | Unset):  Default: 1.
        container_scan_enabled (int | Unset):  Default: 0.
    """

    name: str
    repo_url: str | Unset = ""
    branch: str | Unset = "main"
    ci_platform: str | Unset = "github_actions"
    security_gates_enabled: int | Unset = 1
    sast_enabled: int | Unset = 1
    dast_enabled: int | Unset = 0
    sca_enabled: int | Unset = 1
    secret_scan_enabled: int | Unset = 1
    container_scan_enabled: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        repo_url = self.repo_url

        branch = self.branch

        ci_platform = self.ci_platform

        security_gates_enabled = self.security_gates_enabled

        sast_enabled = self.sast_enabled

        dast_enabled = self.dast_enabled

        sca_enabled = self.sca_enabled

        secret_scan_enabled = self.secret_scan_enabled

        container_scan_enabled = self.container_scan_enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if repo_url is not UNSET:
            field_dict["repo_url"] = repo_url
        if branch is not UNSET:
            field_dict["branch"] = branch
        if ci_platform is not UNSET:
            field_dict["ci_platform"] = ci_platform
        if security_gates_enabled is not UNSET:
            field_dict["security_gates_enabled"] = security_gates_enabled
        if sast_enabled is not UNSET:
            field_dict["sast_enabled"] = sast_enabled
        if dast_enabled is not UNSET:
            field_dict["dast_enabled"] = dast_enabled
        if sca_enabled is not UNSET:
            field_dict["sca_enabled"] = sca_enabled
        if secret_scan_enabled is not UNSET:
            field_dict["secret_scan_enabled"] = secret_scan_enabled
        if container_scan_enabled is not UNSET:
            field_dict["container_scan_enabled"] = container_scan_enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        repo_url = d.pop("repo_url", UNSET)

        branch = d.pop("branch", UNSET)

        ci_platform = d.pop("ci_platform", UNSET)

        security_gates_enabled = d.pop("security_gates_enabled", UNSET)

        sast_enabled = d.pop("sast_enabled", UNSET)

        dast_enabled = d.pop("dast_enabled", UNSET)

        sca_enabled = d.pop("sca_enabled", UNSET)

        secret_scan_enabled = d.pop("secret_scan_enabled", UNSET)

        container_scan_enabled = d.pop("container_scan_enabled", UNSET)

        pipeline_create = cls(
            name=name,
            repo_url=repo_url,
            branch=branch,
            ci_platform=ci_platform,
            security_gates_enabled=security_gates_enabled,
            sast_enabled=sast_enabled,
            dast_enabled=dast_enabled,
            sca_enabled=sca_enabled,
            secret_scan_enabled=secret_scan_enabled,
            container_scan_enabled=container_scan_enabled,
        )

        pipeline_create.additional_properties = d
        return pipeline_create

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
