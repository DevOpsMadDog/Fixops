from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.admission_rule_request_conditions import AdmissionRuleRequestConditions


T = TypeVar("T", bound="AdmissionRuleRequest")


@_attrs_define
class AdmissionRuleRequest:
    """
    Attributes:
        name (str): Unique rule name
        description (str | Unset): Human-readable description Default: ''.
        action (str | Unset): Action on violation: deny | warn | audit Default: 'deny'.
        enabled (bool | Unset):  Default: True.
        conditions (AdmissionRuleRequestConditions | Unset):
    """

    name: str
    description: str | Unset = ""
    action: str | Unset = "deny"
    enabled: bool | Unset = True
    conditions: AdmissionRuleRequestConditions | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        action = self.action

        enabled = self.enabled

        conditions: dict[str, Any] | Unset = UNSET
        if not isinstance(self.conditions, Unset):
            conditions = self.conditions.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if action is not UNSET:
            field_dict["action"] = action
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if conditions is not UNSET:
            field_dict["conditions"] = conditions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.admission_rule_request_conditions import AdmissionRuleRequestConditions

        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description", UNSET)

        action = d.pop("action", UNSET)

        enabled = d.pop("enabled", UNSET)

        _conditions = d.pop("conditions", UNSET)
        conditions: AdmissionRuleRequestConditions | Unset
        if isinstance(_conditions, Unset):
            conditions = UNSET
        else:
            conditions = AdmissionRuleRequestConditions.from_dict(_conditions)

        admission_rule_request = cls(
            name=name,
            description=description,
            action=action,
            enabled=enabled,
            conditions=conditions,
        )

        admission_rule_request.additional_properties = d
        return admission_rule_request

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
