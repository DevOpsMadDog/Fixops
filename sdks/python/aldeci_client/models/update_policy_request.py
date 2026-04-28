from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.policy_decision import PolicyDecision
from ..models.policy_language import PolicyLanguage
from ..models.policy_scope import PolicyScope
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.update_policy_request_rules_type_0_item import UpdatePolicyRequestRulesType0Item


T = TypeVar("T", bound="UpdatePolicyRequest")


@_attrs_define
class UpdatePolicyRequest:
    """
    Attributes:
        name (None | str | Unset):
        description (None | str | Unset):
        scope (None | PolicyScope | Unset):
        language (None | PolicyLanguage | Unset):
        rules (list[UpdatePolicyRequestRulesType0Item] | None | Unset):
        decision_on_match (None | PolicyDecision | Unset):
        enabled (bool | None | Unset):
    """

    name: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    scope: None | PolicyScope | Unset = UNSET
    language: None | PolicyLanguage | Unset = UNSET
    rules: list[UpdatePolicyRequestRulesType0Item] | None | Unset = UNSET
    decision_on_match: None | PolicyDecision | Unset = UNSET
    enabled: bool | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
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

        scope: None | str | Unset
        if isinstance(self.scope, Unset):
            scope = UNSET
        elif isinstance(self.scope, PolicyScope):
            scope = self.scope.value
        else:
            scope = self.scope

        language: None | str | Unset
        if isinstance(self.language, Unset):
            language = UNSET
        elif isinstance(self.language, PolicyLanguage):
            language = self.language.value
        else:
            language = self.language

        rules: list[dict[str, Any]] | None | Unset
        if isinstance(self.rules, Unset):
            rules = UNSET
        elif isinstance(self.rules, list):
            rules = []
            for rules_type_0_item_data in self.rules:
                rules_type_0_item = rules_type_0_item_data.to_dict()
                rules.append(rules_type_0_item)

        else:
            rules = self.rules

        decision_on_match: None | str | Unset
        if isinstance(self.decision_on_match, Unset):
            decision_on_match = UNSET
        elif isinstance(self.decision_on_match, PolicyDecision):
            decision_on_match = self.decision_on_match.value
        else:
            decision_on_match = self.decision_on_match

        enabled: bool | None | Unset
        if isinstance(self.enabled, Unset):
            enabled = UNSET
        else:
            enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if description is not UNSET:
            field_dict["description"] = description
        if scope is not UNSET:
            field_dict["scope"] = scope
        if language is not UNSET:
            field_dict["language"] = language
        if rules is not UNSET:
            field_dict["rules"] = rules
        if decision_on_match is not UNSET:
            field_dict["decision_on_match"] = decision_on_match
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.update_policy_request_rules_type_0_item import UpdatePolicyRequestRulesType0Item

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

        def _parse_scope(data: object) -> None | PolicyScope | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                scope_type_0 = PolicyScope(data)

                return scope_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PolicyScope | Unset, data)

        scope = _parse_scope(d.pop("scope", UNSET))

        def _parse_language(data: object) -> None | PolicyLanguage | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                language_type_0 = PolicyLanguage(data)

                return language_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PolicyLanguage | Unset, data)

        language = _parse_language(d.pop("language", UNSET))

        def _parse_rules(data: object) -> list[UpdatePolicyRequestRulesType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                rules_type_0 = []
                _rules_type_0 = data
                for rules_type_0_item_data in _rules_type_0:
                    rules_type_0_item = UpdatePolicyRequestRulesType0Item.from_dict(rules_type_0_item_data)

                    rules_type_0.append(rules_type_0_item)

                return rules_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[UpdatePolicyRequestRulesType0Item] | None | Unset, data)

        rules = _parse_rules(d.pop("rules", UNSET))

        def _parse_decision_on_match(data: object) -> None | PolicyDecision | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                decision_on_match_type_0 = PolicyDecision(data)

                return decision_on_match_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PolicyDecision | Unset, data)

        decision_on_match = _parse_decision_on_match(d.pop("decision_on_match", UNSET))

        def _parse_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        enabled = _parse_enabled(d.pop("enabled", UNSET))

        update_policy_request = cls(
            name=name,
            description=description,
            scope=scope,
            language=language,
            rules=rules,
            decision_on_match=decision_on_match,
            enabled=enabled,
        )

        update_policy_request.additional_properties = d
        return update_policy_request

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
