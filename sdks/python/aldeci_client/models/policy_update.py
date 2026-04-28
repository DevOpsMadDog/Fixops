from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.policy_status import PolicyStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.policy_update_metadata_type_0 import PolicyUpdateMetadataType0
    from ..models.policy_update_rules_type_0 import PolicyUpdateRulesType0


T = TypeVar("T", bound="PolicyUpdate")


@_attrs_define
class PolicyUpdate:
    """Request model for updating a policy.

    Attributes:
        name (None | str | Unset):
        description (None | str | Unset):
        policy_type (None | str | Unset):
        status (None | PolicyStatus | Unset):
        rules (None | PolicyUpdateRulesType0 | Unset):
        metadata (None | PolicyUpdateMetadataType0 | Unset):
    """

    name: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    policy_type: None | str | Unset = UNSET
    status: None | PolicyStatus | Unset = UNSET
    rules: None | PolicyUpdateRulesType0 | Unset = UNSET
    metadata: None | PolicyUpdateMetadataType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.policy_update_metadata_type_0 import PolicyUpdateMetadataType0
        from ..models.policy_update_rules_type_0 import PolicyUpdateRulesType0

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        policy_type: None | str | Unset
        if isinstance(self.policy_type, Unset):
            policy_type = UNSET
        else:
            policy_type = self.policy_type

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        elif isinstance(self.status, PolicyStatus):
            status = self.status.value
        else:
            status = self.status

        rules: dict[str, Any] | None | Unset
        if isinstance(self.rules, Unset):
            rules = UNSET
        elif isinstance(self.rules, PolicyUpdateRulesType0):
            rules = self.rules.to_dict()
        else:
            rules = self.rules

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, PolicyUpdateMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if description is not UNSET:
            field_dict["description"] = description
        if policy_type is not UNSET:
            field_dict["policy_type"] = policy_type
        if status is not UNSET:
            field_dict["status"] = status
        if rules is not UNSET:
            field_dict["rules"] = rules
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.policy_update_metadata_type_0 import PolicyUpdateMetadataType0
        from ..models.policy_update_rules_type_0 import PolicyUpdateRulesType0

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_policy_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        policy_type = _parse_policy_type(d.pop("policy_type", UNSET))

        def _parse_status(data: object) -> None | PolicyStatus | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                status_type_0 = PolicyStatus(data)

                return status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PolicyStatus | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_rules(data: object) -> None | PolicyUpdateRulesType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                rules_type_0 = PolicyUpdateRulesType0.from_dict(data)

                return rules_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PolicyUpdateRulesType0 | Unset, data)

        rules = _parse_rules(d.pop("rules", UNSET))

        def _parse_metadata(data: object) -> None | PolicyUpdateMetadataType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = PolicyUpdateMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PolicyUpdateMetadataType0 | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        policy_update = cls(
            name=name,
            description=description,
            policy_type=policy_type,
            status=status,
            rules=rules,
            metadata=metadata,
        )

        policy_update.additional_properties = d
        return policy_update

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
