from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_access_policy_request_conditions_type_0 import CreateAccessPolicyRequestConditionsType0


T = TypeVar("T", bound="CreateAccessPolicyRequest")


@_attrs_define
class CreateAccessPolicyRequest:
    """
    Attributes:
        name (str): Policy name
        resource_type (str): file | api | database | network | application | service
        action (str): read | write | execute | delete | admin
        effect (str | Unset): allow | deny Default: 'allow'.
        conditions (CreateAccessPolicyRequestConditionsType0 | None | Unset): Optional policy conditions
    """

    name: str
    resource_type: str
    action: str
    effect: str | Unset = "allow"
    conditions: CreateAccessPolicyRequestConditionsType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.create_access_policy_request_conditions_type_0 import CreateAccessPolicyRequestConditionsType0

        name = self.name

        resource_type = self.resource_type

        action = self.action

        effect = self.effect

        conditions: dict[str, Any] | None | Unset
        if isinstance(self.conditions, Unset):
            conditions = UNSET
        elif isinstance(self.conditions, CreateAccessPolicyRequestConditionsType0):
            conditions = self.conditions.to_dict()
        else:
            conditions = self.conditions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "resource_type": resource_type,
                "action": action,
            }
        )
        if effect is not UNSET:
            field_dict["effect"] = effect
        if conditions is not UNSET:
            field_dict["conditions"] = conditions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_access_policy_request_conditions_type_0 import CreateAccessPolicyRequestConditionsType0

        d = dict(src_dict)
        name = d.pop("name")

        resource_type = d.pop("resource_type")

        action = d.pop("action")

        effect = d.pop("effect", UNSET)

        def _parse_conditions(data: object) -> CreateAccessPolicyRequestConditionsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                conditions_type_0 = CreateAccessPolicyRequestConditionsType0.from_dict(data)

                return conditions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CreateAccessPolicyRequestConditionsType0 | None | Unset, data)

        conditions = _parse_conditions(d.pop("conditions", UNSET))

        create_access_policy_request = cls(
            name=name,
            resource_type=resource_type,
            action=action,
            effect=effect,
            conditions=conditions,
        )

        create_access_policy_request.additional_properties = d
        return create_access_policy_request

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
