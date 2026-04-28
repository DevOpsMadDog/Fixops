from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreatePRRequest")


@_attrs_define
class CreatePRRequest:
    """Request to create pull request.

    Attributes:
        finding_ids (list[str]):
        repository (str):
        branch (str | Unset):  Default: 'security-fixes'.
        auto_merge (bool | Unset):  Default: False.
    """

    finding_ids: list[str]
    repository: str
    branch: str | Unset = "security-fixes"
    auto_merge: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_ids = self.finding_ids

        repository = self.repository

        branch = self.branch

        auto_merge = self.auto_merge

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_ids": finding_ids,
                "repository": repository,
            }
        )
        if branch is not UNSET:
            field_dict["branch"] = branch
        if auto_merge is not UNSET:
            field_dict["auto_merge"] = auto_merge

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_ids = cast(list[str], d.pop("finding_ids"))

        repository = d.pop("repository")

        branch = d.pop("branch", UNSET)

        auto_merge = d.pop("auto_merge", UNSET)

        create_pr_request = cls(
            finding_ids=finding_ids,
            repository=repository,
            branch=branch,
            auto_merge=auto_merge,
        )

        create_pr_request.additional_properties = d
        return create_pr_request

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
