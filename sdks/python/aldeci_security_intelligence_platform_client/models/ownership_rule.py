from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="OwnershipRule")


@_attrs_define
class OwnershipRule:
    """A CODEOWNERS-style rule: glob pattern → owner email with priority.

    Attributes:
        pattern (str): Glob pattern (e.g. 'src/core/**')
        owner_email (str): Email of the assigned owner
        id (str | Unset):
        priority (int | Unset): Higher priority rules win when multiple patterns match Default: 0.
        created_at (str | Unset):
    """

    pattern: str
    owner_email: str
    id: str | Unset = UNSET
    priority: int | Unset = 0
    created_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        pattern = self.pattern

        owner_email = self.owner_email

        id = self.id

        priority = self.priority

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "pattern": pattern,
                "owner_email": owner_email,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if priority is not UNSET:
            field_dict["priority"] = priority
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        pattern = d.pop("pattern")

        owner_email = d.pop("owner_email")

        id = d.pop("id", UNSET)

        priority = d.pop("priority", UNSET)

        created_at = d.pop("created_at", UNSET)

        ownership_rule = cls(
            pattern=pattern,
            owner_email=owner_email,
            id=id,
            priority=priority,
            created_at=created_at,
        )

        ownership_rule.additional_properties = d
        return ownership_rule

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
