from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.impact_response_compliance_impact_item import ImpactResponseComplianceImpactItem
    from ..models.impact_response_data_flows_item import ImpactResponseDataFlowsItem
    from ..models.impact_response_downstream_consumers_item import ImpactResponseDownstreamConsumersItem
    from ..models.impact_response_upstream_dependencies_item import ImpactResponseUpstreamDependenciesItem


T = TypeVar("T", bound="ImpactResponse")


@_attrs_define
class ImpactResponse:
    """Blast radius analysis response.

    Attributes:
        entity_id (str):
        available (bool):
        blast_radius (int):
        upstream_dependencies (list[ImpactResponseUpstreamDependenciesItem] | Unset):
        downstream_consumers (list[ImpactResponseDownstreamConsumersItem] | Unset):
        data_flows (list[ImpactResponseDataFlowsItem] | Unset):
        compliance_impact (list[ImpactResponseComplianceImpactItem] | Unset):
        risk_weight (float | Unset):  Default: 0.0.
        summary (str | Unset):  Default: ''.
    """

    entity_id: str
    available: bool
    blast_radius: int
    upstream_dependencies: list[ImpactResponseUpstreamDependenciesItem] | Unset = UNSET
    downstream_consumers: list[ImpactResponseDownstreamConsumersItem] | Unset = UNSET
    data_flows: list[ImpactResponseDataFlowsItem] | Unset = UNSET
    compliance_impact: list[ImpactResponseComplianceImpactItem] | Unset = UNSET
    risk_weight: float | Unset = 0.0
    summary: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_id = self.entity_id

        available = self.available

        blast_radius = self.blast_radius

        upstream_dependencies: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.upstream_dependencies, Unset):
            upstream_dependencies = []
            for upstream_dependencies_item_data in self.upstream_dependencies:
                upstream_dependencies_item = upstream_dependencies_item_data.to_dict()
                upstream_dependencies.append(upstream_dependencies_item)

        downstream_consumers: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.downstream_consumers, Unset):
            downstream_consumers = []
            for downstream_consumers_item_data in self.downstream_consumers:
                downstream_consumers_item = downstream_consumers_item_data.to_dict()
                downstream_consumers.append(downstream_consumers_item)

        data_flows: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.data_flows, Unset):
            data_flows = []
            for data_flows_item_data in self.data_flows:
                data_flows_item = data_flows_item_data.to_dict()
                data_flows.append(data_flows_item)

        compliance_impact: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.compliance_impact, Unset):
            compliance_impact = []
            for compliance_impact_item_data in self.compliance_impact:
                compliance_impact_item = compliance_impact_item_data.to_dict()
                compliance_impact.append(compliance_impact_item)

        risk_weight = self.risk_weight

        summary = self.summary

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_id": entity_id,
                "available": available,
                "blast_radius": blast_radius,
            }
        )
        if upstream_dependencies is not UNSET:
            field_dict["upstream_dependencies"] = upstream_dependencies
        if downstream_consumers is not UNSET:
            field_dict["downstream_consumers"] = downstream_consumers
        if data_flows is not UNSET:
            field_dict["data_flows"] = data_flows
        if compliance_impact is not UNSET:
            field_dict["compliance_impact"] = compliance_impact
        if risk_weight is not UNSET:
            field_dict["risk_weight"] = risk_weight
        if summary is not UNSET:
            field_dict["summary"] = summary

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.impact_response_compliance_impact_item import ImpactResponseComplianceImpactItem
        from ..models.impact_response_data_flows_item import ImpactResponseDataFlowsItem
        from ..models.impact_response_downstream_consumers_item import ImpactResponseDownstreamConsumersItem
        from ..models.impact_response_upstream_dependencies_item import ImpactResponseUpstreamDependenciesItem

        d = dict(src_dict)
        entity_id = d.pop("entity_id")

        available = d.pop("available")

        blast_radius = d.pop("blast_radius")

        _upstream_dependencies = d.pop("upstream_dependencies", UNSET)
        upstream_dependencies: list[ImpactResponseUpstreamDependenciesItem] | Unset = UNSET
        if _upstream_dependencies is not UNSET:
            upstream_dependencies = []
            for upstream_dependencies_item_data in _upstream_dependencies:
                upstream_dependencies_item = ImpactResponseUpstreamDependenciesItem.from_dict(
                    upstream_dependencies_item_data
                )

                upstream_dependencies.append(upstream_dependencies_item)

        _downstream_consumers = d.pop("downstream_consumers", UNSET)
        downstream_consumers: list[ImpactResponseDownstreamConsumersItem] | Unset = UNSET
        if _downstream_consumers is not UNSET:
            downstream_consumers = []
            for downstream_consumers_item_data in _downstream_consumers:
                downstream_consumers_item = ImpactResponseDownstreamConsumersItem.from_dict(
                    downstream_consumers_item_data
                )

                downstream_consumers.append(downstream_consumers_item)

        _data_flows = d.pop("data_flows", UNSET)
        data_flows: list[ImpactResponseDataFlowsItem] | Unset = UNSET
        if _data_flows is not UNSET:
            data_flows = []
            for data_flows_item_data in _data_flows:
                data_flows_item = ImpactResponseDataFlowsItem.from_dict(data_flows_item_data)

                data_flows.append(data_flows_item)

        _compliance_impact = d.pop("compliance_impact", UNSET)
        compliance_impact: list[ImpactResponseComplianceImpactItem] | Unset = UNSET
        if _compliance_impact is not UNSET:
            compliance_impact = []
            for compliance_impact_item_data in _compliance_impact:
                compliance_impact_item = ImpactResponseComplianceImpactItem.from_dict(compliance_impact_item_data)

                compliance_impact.append(compliance_impact_item)

        risk_weight = d.pop("risk_weight", UNSET)

        summary = d.pop("summary", UNSET)

        impact_response = cls(
            entity_id=entity_id,
            available=available,
            blast_radius=blast_radius,
            upstream_dependencies=upstream_dependencies,
            downstream_consumers=downstream_consumers,
            data_flows=data_flows,
            compliance_impact=compliance_impact,
            risk_weight=risk_weight,
            summary=summary,
        )

        impact_response.additional_properties = d
        return impact_response

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
