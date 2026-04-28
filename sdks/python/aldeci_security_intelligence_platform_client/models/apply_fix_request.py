from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ApplyFixRequest")


@_attrs_define
class ApplyFixRequest:
    """Request to apply a generated fix.

    Attributes:
        fix_id (str): ID of the previously generated fix
        repository (str): Repository slug (owner/repo)
        create_pr (bool | Unset): Whether to create a pull request Default: True.
        auto_merge (bool | Unset): Auto-merge if high confidence Default: False.
    """

    fix_id: str
    repository: str
    create_pr: bool | Unset = True
    auto_merge: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        fix_id = self.fix_id

        repository = self.repository

        create_pr = self.create_pr

        auto_merge = self.auto_merge

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "fix_id": fix_id,
                "repository": repository,
            }
        )
        if create_pr is not UNSET:
            field_dict["create_pr"] = create_pr
        if auto_merge is not UNSET:
            field_dict["auto_merge"] = auto_merge

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        fix_id = d.pop("fix_id")

        repository = d.pop("repository")

        create_pr = d.pop("create_pr", UNSET)

        auto_merge = d.pop("auto_merge", UNSET)

        apply_fix_request = cls(
            fix_id=fix_id,
            repository=repository,
            create_pr=create_pr,
            auto_merge=auto_merge,
        )

        apply_fix_request.additional_properties = d
        return apply_fix_request

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
