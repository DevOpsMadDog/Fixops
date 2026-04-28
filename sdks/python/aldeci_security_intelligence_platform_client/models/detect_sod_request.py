from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.sod_rule import SodRule


T = TypeVar("T", bound="DetectSodRequest")


@_attrs_define
class DetectSodRequest:
    """
    Attributes:
        user_id (str): User ID to check
        sod_rules (list[SodRule]): List of SoD rules to evaluate
    """

    user_id: str
    sod_rules: list[SodRule]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        sod_rules = []
        for sod_rules_item_data in self.sod_rules:
            sod_rules_item = sod_rules_item_data.to_dict()
            sod_rules.append(sod_rules_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "sod_rules": sod_rules,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sod_rule import SodRule

        d = dict(src_dict)
        user_id = d.pop("user_id")

        sod_rules = []
        _sod_rules = d.pop("sod_rules")
        for sod_rules_item_data in _sod_rules:
            sod_rules_item = SodRule.from_dict(sod_rules_item_data)

            sod_rules.append(sod_rules_item)

        detect_sod_request = cls(
            user_id=user_id,
            sod_rules=sod_rules,
        )

        detect_sod_request.additional_properties = d
        return detect_sod_request

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
