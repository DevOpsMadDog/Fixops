from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.toxic_combo_rule_predicates_item import ToxicComboRulePredicatesItem


T = TypeVar("T", bound="ToxicComboRule")


@_attrs_define
class ToxicComboRule:
    """POST /api/v1/toxic-combo-rules body.

    Attributes:
        combo_id (str):
        name (str):
        predicates (list[ToxicComboRulePredicatesItem]): Predicate clauses (attribute + operator + value)
        description (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'high'.
        require_all (bool | Unset):  Default: True.
    """

    combo_id: str
    name: str
    predicates: list[ToxicComboRulePredicatesItem]
    description: str | Unset = ""
    severity: str | Unset = "high"
    require_all: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        combo_id = self.combo_id

        name = self.name

        predicates = []
        for predicates_item_data in self.predicates:
            predicates_item = predicates_item_data.to_dict()
            predicates.append(predicates_item)

        description = self.description

        severity = self.severity

        require_all = self.require_all

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "combo_id": combo_id,
                "name": name,
                "predicates": predicates,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if severity is not UNSET:
            field_dict["severity"] = severity
        if require_all is not UNSET:
            field_dict["require_all"] = require_all

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.toxic_combo_rule_predicates_item import ToxicComboRulePredicatesItem

        d = dict(src_dict)
        combo_id = d.pop("combo_id")

        name = d.pop("name")

        predicates = []
        _predicates = d.pop("predicates")
        for predicates_item_data in _predicates:
            predicates_item = ToxicComboRulePredicatesItem.from_dict(predicates_item_data)

            predicates.append(predicates_item)

        description = d.pop("description", UNSET)

        severity = d.pop("severity", UNSET)

        require_all = d.pop("require_all", UNSET)

        toxic_combo_rule = cls(
            combo_id=combo_id,
            name=name,
            predicates=predicates,
            description=description,
            severity=severity,
            require_all=require_all,
        )

        toxic_combo_rule.additional_properties = d
        return toxic_combo_rule

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
