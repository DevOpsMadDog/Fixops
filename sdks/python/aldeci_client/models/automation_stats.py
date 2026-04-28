from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.automation_stats_top_rules_item import AutomationStatsTopRulesItem


T = TypeVar("T", bound="AutomationStats")


@_attrs_define
class AutomationStats:
    """
    Attributes:
        org_id (str):
        total_rules (int):
        enabled_rules (int):
        total_executions (int):
        findings_auto_processed (int):
        estimated_minutes_saved (float):
        top_rules (list[AutomationStatsTopRulesItem] | Unset):
    """

    org_id: str
    total_rules: int
    enabled_rules: int
    total_executions: int
    findings_auto_processed: int
    estimated_minutes_saved: float
    top_rules: list[AutomationStatsTopRulesItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total_rules = self.total_rules

        enabled_rules = self.enabled_rules

        total_executions = self.total_executions

        findings_auto_processed = self.findings_auto_processed

        estimated_minutes_saved = self.estimated_minutes_saved

        top_rules: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.top_rules, Unset):
            top_rules = []
            for top_rules_item_data in self.top_rules:
                top_rules_item = top_rules_item_data.to_dict()
                top_rules.append(top_rules_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total_rules": total_rules,
                "enabled_rules": enabled_rules,
                "total_executions": total_executions,
                "findings_auto_processed": findings_auto_processed,
                "estimated_minutes_saved": estimated_minutes_saved,
            }
        )
        if top_rules is not UNSET:
            field_dict["top_rules"] = top_rules

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.automation_stats_top_rules_item import AutomationStatsTopRulesItem

        d = dict(src_dict)
        org_id = d.pop("org_id")

        total_rules = d.pop("total_rules")

        enabled_rules = d.pop("enabled_rules")

        total_executions = d.pop("total_executions")

        findings_auto_processed = d.pop("findings_auto_processed")

        estimated_minutes_saved = d.pop("estimated_minutes_saved")

        _top_rules = d.pop("top_rules", UNSET)
        top_rules: list[AutomationStatsTopRulesItem] | Unset = UNSET
        if _top_rules is not UNSET:
            top_rules = []
            for top_rules_item_data in _top_rules:
                top_rules_item = AutomationStatsTopRulesItem.from_dict(top_rules_item_data)

                top_rules.append(top_rules_item)

        automation_stats = cls(
            org_id=org_id,
            total_rules=total_rules,
            enabled_rules=enabled_rules,
            total_executions=total_executions,
            findings_auto_processed=findings_auto_processed,
            estimated_minutes_saved=estimated_minutes_saved,
            top_rules=top_rules,
        )

        automation_stats.additional_properties = d
        return automation_stats

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
