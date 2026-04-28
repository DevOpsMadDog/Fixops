from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RunTrigger")


@_attrs_define
class RunTrigger:
    """
    Attributes:
        triggered_by (str | Unset):  Default: 'manual'.
        commit_sha (str | Unset):  Default: ''.
        branch (str | Unset):  Default: 'main'.
    """

    triggered_by: str | Unset = "manual"
    commit_sha: str | Unset = ""
    branch: str | Unset = "main"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        triggered_by = self.triggered_by

        commit_sha = self.commit_sha

        branch = self.branch

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if triggered_by is not UNSET:
            field_dict["triggered_by"] = triggered_by
        if commit_sha is not UNSET:
            field_dict["commit_sha"] = commit_sha
        if branch is not UNSET:
            field_dict["branch"] = branch

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        triggered_by = d.pop("triggered_by", UNSET)

        commit_sha = d.pop("commit_sha", UNSET)

        branch = d.pop("branch", UNSET)

        run_trigger = cls(
            triggered_by=triggered_by,
            commit_sha=commit_sha,
            branch=branch,
        )

        run_trigger.additional_properties = d
        return run_trigger

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
