from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.entity_type import EntityType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.auto_tag_rule_conditions import AutoTagRuleConditions


T = TypeVar("T", bound="AutoTagRule")


@_attrs_define
class AutoTagRule:
    """
    Attributes:
        name (str):
        entity_type (EntityType):
        id (str | Unset):
        conditions (AutoTagRuleConditions | Unset): field/op/value conditions
        tags_to_apply (list[str] | Unset): Tag IDs to apply
        enabled (bool | Unset):  Default: True.
        org_id (str | Unset):  Default: 'default'.
        created_at (str | Unset):
    """

    name: str
    entity_type: EntityType
    id: str | Unset = UNSET
    conditions: AutoTagRuleConditions | Unset = UNSET
    tags_to_apply: list[str] | Unset = UNSET
    enabled: bool | Unset = True
    org_id: str | Unset = "default"
    created_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        entity_type = self.entity_type.value

        id = self.id

        conditions: dict[str, Any] | Unset = UNSET
        if not isinstance(self.conditions, Unset):
            conditions = self.conditions.to_dict()

        tags_to_apply: list[str] | Unset = UNSET
        if not isinstance(self.tags_to_apply, Unset):
            tags_to_apply = self.tags_to_apply

        enabled = self.enabled

        org_id = self.org_id

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "entity_type": entity_type,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if conditions is not UNSET:
            field_dict["conditions"] = conditions
        if tags_to_apply is not UNSET:
            field_dict["tags_to_apply"] = tags_to_apply
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.auto_tag_rule_conditions import AutoTagRuleConditions

        d = dict(src_dict)
        name = d.pop("name")

        entity_type = EntityType(d.pop("entity_type"))

        id = d.pop("id", UNSET)

        _conditions = d.pop("conditions", UNSET)
        conditions: AutoTagRuleConditions | Unset
        if isinstance(_conditions, Unset):
            conditions = UNSET
        else:
            conditions = AutoTagRuleConditions.from_dict(_conditions)

        tags_to_apply = cast(list[str], d.pop("tags_to_apply", UNSET))

        enabled = d.pop("enabled", UNSET)

        org_id = d.pop("org_id", UNSET)

        created_at = d.pop("created_at", UNSET)

        auto_tag_rule = cls(
            name=name,
            entity_type=entity_type,
            id=id,
            conditions=conditions,
            tags_to_apply=tags_to_apply,
            enabled=enabled,
            org_id=org_id,
            created_at=created_at,
        )

        auto_tag_rule.additional_properties = d
        return auto_tag_rule

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
