from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.update_rule_request_criteria_type_0 import UpdateRuleRequestCriteriaType0


T = TypeVar("T", bound="UpdateRuleRequest")


@_attrs_define
class UpdateRuleRequest:
    """
    Attributes:
        name (None | str | Unset):
        description (None | str | Unset):
        criteria (None | Unset | UpdateRuleRequestCriteriaType0):
        action (None | str | Unset):
        downgrade_to (None | str | Unset):
        defer_days (int | None | Unset):
        expires_at (datetime.datetime | None | Unset):
        enabled (bool | None | Unset):
    """

    name: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    criteria: None | Unset | UpdateRuleRequestCriteriaType0 = UNSET
    action: None | str | Unset = UNSET
    downgrade_to: None | str | Unset = UNSET
    defer_days: int | None | Unset = UNSET
    expires_at: datetime.datetime | None | Unset = UNSET
    enabled: bool | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.update_rule_request_criteria_type_0 import UpdateRuleRequestCriteriaType0

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

        criteria: dict[str, Any] | None | Unset
        if isinstance(self.criteria, Unset):
            criteria = UNSET
        elif isinstance(self.criteria, UpdateRuleRequestCriteriaType0):
            criteria = self.criteria.to_dict()
        else:
            criteria = self.criteria

        action: None | str | Unset
        if isinstance(self.action, Unset):
            action = UNSET
        else:
            action = self.action

        downgrade_to: None | str | Unset
        if isinstance(self.downgrade_to, Unset):
            downgrade_to = UNSET
        else:
            downgrade_to = self.downgrade_to

        defer_days: int | None | Unset
        if isinstance(self.defer_days, Unset):
            defer_days = UNSET
        else:
            defer_days = self.defer_days

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        elif isinstance(self.expires_at, datetime.datetime):
            expires_at = self.expires_at.isoformat()
        else:
            expires_at = self.expires_at

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
        if criteria is not UNSET:
            field_dict["criteria"] = criteria
        if action is not UNSET:
            field_dict["action"] = action
        if downgrade_to is not UNSET:
            field_dict["downgrade_to"] = downgrade_to
        if defer_days is not UNSET:
            field_dict["defer_days"] = defer_days
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.update_rule_request_criteria_type_0 import UpdateRuleRequestCriteriaType0

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

        def _parse_criteria(data: object) -> None | Unset | UpdateRuleRequestCriteriaType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                criteria_type_0 = UpdateRuleRequestCriteriaType0.from_dict(data)

                return criteria_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UpdateRuleRequestCriteriaType0, data)

        criteria = _parse_criteria(d.pop("criteria", UNSET))

        def _parse_action(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        action = _parse_action(d.pop("action", UNSET))

        def _parse_downgrade_to(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        downgrade_to = _parse_downgrade_to(d.pop("downgrade_to", UNSET))

        def _parse_defer_days(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        defer_days = _parse_defer_days(d.pop("defer_days", UNSET))

        def _parse_expires_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                expires_at_type_0 = isoparse(data)

                return expires_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        def _parse_enabled(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        enabled = _parse_enabled(d.pop("enabled", UNSET))

        update_rule_request = cls(
            name=name,
            description=description,
            criteria=criteria,
            action=action,
            downgrade_to=downgrade_to,
            defer_days=defer_days,
            expires_at=expires_at,
            enabled=enabled,
        )

        update_rule_request.additional_properties = d
        return update_rule_request

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
