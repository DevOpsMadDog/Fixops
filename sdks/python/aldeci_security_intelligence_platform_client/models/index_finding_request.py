from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IndexFindingRequest")


@_attrs_define
class IndexFindingRequest:
    """
    Attributes:
        finding_id (str):
        commit_sha (None | str | Unset):
        artifact_id (None | str | Unset):
        deployment_id (None | str | Unset):
    """

    finding_id: str
    commit_sha: None | str | Unset = UNSET
    artifact_id: None | str | Unset = UNSET
    deployment_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        commit_sha: None | str | Unset
        if isinstance(self.commit_sha, Unset):
            commit_sha = UNSET
        else:
            commit_sha = self.commit_sha

        artifact_id: None | str | Unset
        if isinstance(self.artifact_id, Unset):
            artifact_id = UNSET
        else:
            artifact_id = self.artifact_id

        deployment_id: None | str | Unset
        if isinstance(self.deployment_id, Unset):
            deployment_id = UNSET
        else:
            deployment_id = self.deployment_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
            }
        )
        if commit_sha is not UNSET:
            field_dict["commit_sha"] = commit_sha
        if artifact_id is not UNSET:
            field_dict["artifact_id"] = artifact_id
        if deployment_id is not UNSET:
            field_dict["deployment_id"] = deployment_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        def _parse_commit_sha(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        commit_sha = _parse_commit_sha(d.pop("commit_sha", UNSET))

        def _parse_artifact_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        artifact_id = _parse_artifact_id(d.pop("artifact_id", UNSET))

        def _parse_deployment_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        deployment_id = _parse_deployment_id(d.pop("deployment_id", UNSET))

        index_finding_request = cls(
            finding_id=finding_id,
            commit_sha=commit_sha,
            artifact_id=artifact_id,
            deployment_id=deployment_id,
        )

        index_finding_request.additional_properties = d
        return index_finding_request

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
