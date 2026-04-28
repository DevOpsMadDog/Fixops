from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="MgrPolicyResponse")


@_attrs_define
class MgrPolicyResponse:
    """
    Attributes:
        id (str):
        name (str):
        description (str):
        categories (list[str]):
        max_age_days (int):
        require_rotation (bool):
        block_on_commit (bool):
        compliance_frameworks (list[str]):
        created_at (str):
    """

    id: str
    name: str
    description: str
    categories: list[str]
    max_age_days: int
    require_rotation: bool
    block_on_commit: bool
    compliance_frameworks: list[str]
    created_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        description = self.description

        categories = self.categories

        max_age_days = self.max_age_days

        require_rotation = self.require_rotation

        block_on_commit = self.block_on_commit

        compliance_frameworks = self.compliance_frameworks

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "description": description,
                "categories": categories,
                "max_age_days": max_age_days,
                "require_rotation": require_rotation,
                "block_on_commit": block_on_commit,
                "compliance_frameworks": compliance_frameworks,
                "created_at": created_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        description = d.pop("description")

        categories = cast(list[str], d.pop("categories"))

        max_age_days = d.pop("max_age_days")

        require_rotation = d.pop("require_rotation")

        block_on_commit = d.pop("block_on_commit")

        compliance_frameworks = cast(list[str], d.pop("compliance_frameworks"))

        created_at = d.pop("created_at")

        mgr_policy_response = cls(
            id=id,
            name=name,
            description=description,
            categories=categories,
            max_age_days=max_age_days,
            require_rotation=require_rotation,
            block_on_commit=block_on_commit,
            compliance_frameworks=compliance_frameworks,
            created_at=created_at,
        )

        mgr_policy_response.additional_properties = d
        return mgr_policy_response

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
