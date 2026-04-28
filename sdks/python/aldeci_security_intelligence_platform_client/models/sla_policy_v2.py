from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.escalation_rule import EscalationRule
    from ..models.sla_policy_v2_framework_overrides import SLAPolicyV2FrameworkOverrides
    from ..models.sla_policy_v2_severity_deadlines import SLAPolicyV2SeverityDeadlines


T = TypeVar("T", bound="SLAPolicyV2")


@_attrs_define
class SLAPolicyV2:
    """Extended SLA policy with business hours and framework support.

    Attributes:
        org_id (str):
        name (str):
        id (str | Unset):
        team_id (None | str | Unset):
        asset_tier (None | str | Unset):
        severity_deadlines (SLAPolicyV2SeverityDeadlines | Unset):
        framework_overrides (SLAPolicyV2FrameworkOverrides | Unset):
        business_hours_only (bool | Unset):  Default: False.
        tz_name (str | Unset):  Default: 'UTC'.
        escalation_rules (list[EscalationRule] | Unset):
        enabled (bool | Unset):  Default: True.
        created_at (datetime.datetime | Unset):
        updated_at (datetime.datetime | Unset):
    """

    org_id: str
    name: str
    id: str | Unset = UNSET
    team_id: None | str | Unset = UNSET
    asset_tier: None | str | Unset = UNSET
    severity_deadlines: SLAPolicyV2SeverityDeadlines | Unset = UNSET
    framework_overrides: SLAPolicyV2FrameworkOverrides | Unset = UNSET
    business_hours_only: bool | Unset = False
    tz_name: str | Unset = "UTC"
    escalation_rules: list[EscalationRule] | Unset = UNSET
    enabled: bool | Unset = True
    created_at: datetime.datetime | Unset = UNSET
    updated_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        name = self.name

        id = self.id

        team_id: None | str | Unset
        if isinstance(self.team_id, Unset):
            team_id = UNSET
        else:
            team_id = self.team_id

        asset_tier: None | str | Unset
        if isinstance(self.asset_tier, Unset):
            asset_tier = UNSET
        else:
            asset_tier = self.asset_tier

        severity_deadlines: dict[str, Any] | Unset = UNSET
        if not isinstance(self.severity_deadlines, Unset):
            severity_deadlines = self.severity_deadlines.to_dict()

        framework_overrides: dict[str, Any] | Unset = UNSET
        if not isinstance(self.framework_overrides, Unset):
            framework_overrides = self.framework_overrides.to_dict()

        business_hours_only = self.business_hours_only

        tz_name = self.tz_name

        escalation_rules: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.escalation_rules, Unset):
            escalation_rules = []
            for escalation_rules_item_data in self.escalation_rules:
                escalation_rules_item = escalation_rules_item_data.to_dict()
                escalation_rules.append(escalation_rules_item)

        enabled = self.enabled

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        updated_at: str | Unset = UNSET
        if not isinstance(self.updated_at, Unset):
            updated_at = self.updated_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "name": name,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if team_id is not UNSET:
            field_dict["team_id"] = team_id
        if asset_tier is not UNSET:
            field_dict["asset_tier"] = asset_tier
        if severity_deadlines is not UNSET:
            field_dict["severity_deadlines"] = severity_deadlines
        if framework_overrides is not UNSET:
            field_dict["framework_overrides"] = framework_overrides
        if business_hours_only is not UNSET:
            field_dict["business_hours_only"] = business_hours_only
        if tz_name is not UNSET:
            field_dict["tz_name"] = tz_name
        if escalation_rules is not UNSET:
            field_dict["escalation_rules"] = escalation_rules
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.escalation_rule import EscalationRule
        from ..models.sla_policy_v2_framework_overrides import SLAPolicyV2FrameworkOverrides
        from ..models.sla_policy_v2_severity_deadlines import SLAPolicyV2SeverityDeadlines

        d = dict(src_dict)
        org_id = d.pop("org_id")

        name = d.pop("name")

        id = d.pop("id", UNSET)

        def _parse_team_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        team_id = _parse_team_id(d.pop("team_id", UNSET))

        def _parse_asset_tier(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_tier = _parse_asset_tier(d.pop("asset_tier", UNSET))

        _severity_deadlines = d.pop("severity_deadlines", UNSET)
        severity_deadlines: SLAPolicyV2SeverityDeadlines | Unset
        if isinstance(_severity_deadlines, Unset):
            severity_deadlines = UNSET
        else:
            severity_deadlines = SLAPolicyV2SeverityDeadlines.from_dict(_severity_deadlines)

        _framework_overrides = d.pop("framework_overrides", UNSET)
        framework_overrides: SLAPolicyV2FrameworkOverrides | Unset
        if isinstance(_framework_overrides, Unset):
            framework_overrides = UNSET
        else:
            framework_overrides = SLAPolicyV2FrameworkOverrides.from_dict(_framework_overrides)

        business_hours_only = d.pop("business_hours_only", UNSET)

        tz_name = d.pop("tz_name", UNSET)

        _escalation_rules = d.pop("escalation_rules", UNSET)
        escalation_rules: list[EscalationRule] | Unset = UNSET
        if _escalation_rules is not UNSET:
            escalation_rules = []
            for escalation_rules_item_data in _escalation_rules:
                escalation_rules_item = EscalationRule.from_dict(escalation_rules_item_data)

                escalation_rules.append(escalation_rules_item)

        enabled = d.pop("enabled", UNSET)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        _updated_at = d.pop("updated_at", UNSET)
        updated_at: datetime.datetime | Unset
        if isinstance(_updated_at, Unset):
            updated_at = UNSET
        else:
            updated_at = isoparse(_updated_at)

        sla_policy_v2 = cls(
            org_id=org_id,
            name=name,
            id=id,
            team_id=team_id,
            asset_tier=asset_tier,
            severity_deadlines=severity_deadlines,
            framework_overrides=framework_overrides,
            business_hours_only=business_hours_only,
            tz_name=tz_name,
            escalation_rules=escalation_rules,
            enabled=enabled,
            created_at=created_at,
            updated_at=updated_at,
        )

        sla_policy_v2.additional_properties = d
        return sla_policy_v2

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
