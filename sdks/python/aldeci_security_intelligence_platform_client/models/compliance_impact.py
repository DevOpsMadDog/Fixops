from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.compliance_impact_control_mappings_item import ComplianceImpactControlMappingsItem


T = TypeVar("T", bound="ComplianceImpact")


@_attrs_define
class ComplianceImpact:
    """Compliance framework impact for a finding.

    Attributes:
        frameworks_affected (list[str] | Unset):
        control_mappings (list[ComplianceImpactControlMappingsItem] | Unset):
        compliance_gaps (list[str] | Unset):
    """

    frameworks_affected: list[str] | Unset = UNSET
    control_mappings: list[ComplianceImpactControlMappingsItem] | Unset = UNSET
    compliance_gaps: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        frameworks_affected: list[str] | Unset = UNSET
        if not isinstance(self.frameworks_affected, Unset):
            frameworks_affected = self.frameworks_affected

        control_mappings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.control_mappings, Unset):
            control_mappings = []
            for control_mappings_item_data in self.control_mappings:
                control_mappings_item = control_mappings_item_data.to_dict()
                control_mappings.append(control_mappings_item)

        compliance_gaps: list[str] | Unset = UNSET
        if not isinstance(self.compliance_gaps, Unset):
            compliance_gaps = self.compliance_gaps

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if frameworks_affected is not UNSET:
            field_dict["frameworks_affected"] = frameworks_affected
        if control_mappings is not UNSET:
            field_dict["control_mappings"] = control_mappings
        if compliance_gaps is not UNSET:
            field_dict["compliance_gaps"] = compliance_gaps

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.compliance_impact_control_mappings_item import ComplianceImpactControlMappingsItem

        d = dict(src_dict)
        frameworks_affected = cast(list[str], d.pop("frameworks_affected", UNSET))

        _control_mappings = d.pop("control_mappings", UNSET)
        control_mappings: list[ComplianceImpactControlMappingsItem] | Unset = UNSET
        if _control_mappings is not UNSET:
            control_mappings = []
            for control_mappings_item_data in _control_mappings:
                control_mappings_item = ComplianceImpactControlMappingsItem.from_dict(control_mappings_item_data)

                control_mappings.append(control_mappings_item)

        compliance_gaps = cast(list[str], d.pop("compliance_gaps", UNSET))

        compliance_impact = cls(
            frameworks_affected=frameworks_affected,
            control_mappings=control_mappings,
            compliance_gaps=compliance_gaps,
        )

        compliance_impact.additional_properties = d
        return compliance_impact

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
