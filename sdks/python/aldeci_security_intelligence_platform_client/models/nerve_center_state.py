from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.auto_remediation_action import AutoRemediationAction
    from ..models.intelligence_link import IntelligenceLink
    from ..models.nerve_center_state_compliance_posture import NerveCenterStateCompliancePosture
    from ..models.nerve_center_state_decision_engine import NerveCenterStateDecisionEngine
    from ..models.nerve_center_state_pipeline_throughput import NerveCenterStatePipelineThroughput
    from ..models.suite_status import SuiteStatus
    from ..models.threat_pulse import ThreatPulse


T = TypeVar("T", bound="NerveCenterState")


@_attrs_define
class NerveCenterState:
    """
    Attributes:
        threat_pulse (ThreatPulse): Real-time threat level across all suites.
        suites (list[SuiteStatus]):
        intelligence_links (list[IntelligenceLink]):
        recent_actions (list[AutoRemediationAction]):
        pipeline_throughput (NerveCenterStatePipelineThroughput):
        decision_engine (NerveCenterStateDecisionEngine):
        compliance_posture (NerveCenterStateCompliancePosture):
    """

    threat_pulse: ThreatPulse
    suites: list[SuiteStatus]
    intelligence_links: list[IntelligenceLink]
    recent_actions: list[AutoRemediationAction]
    pipeline_throughput: NerveCenterStatePipelineThroughput
    decision_engine: NerveCenterStateDecisionEngine
    compliance_posture: NerveCenterStateCompliancePosture
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        threat_pulse = self.threat_pulse.to_dict()

        suites = []
        for suites_item_data in self.suites:
            suites_item = suites_item_data.to_dict()
            suites.append(suites_item)

        intelligence_links = []
        for intelligence_links_item_data in self.intelligence_links:
            intelligence_links_item = intelligence_links_item_data.to_dict()
            intelligence_links.append(intelligence_links_item)

        recent_actions = []
        for recent_actions_item_data in self.recent_actions:
            recent_actions_item = recent_actions_item_data.to_dict()
            recent_actions.append(recent_actions_item)

        pipeline_throughput = self.pipeline_throughput.to_dict()

        decision_engine = self.decision_engine.to_dict()

        compliance_posture = self.compliance_posture.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "threat_pulse": threat_pulse,
                "suites": suites,
                "intelligence_links": intelligence_links,
                "recent_actions": recent_actions,
                "pipeline_throughput": pipeline_throughput,
                "decision_engine": decision_engine,
                "compliance_posture": compliance_posture,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.auto_remediation_action import AutoRemediationAction
        from ..models.intelligence_link import IntelligenceLink
        from ..models.nerve_center_state_compliance_posture import NerveCenterStateCompliancePosture
        from ..models.nerve_center_state_decision_engine import NerveCenterStateDecisionEngine
        from ..models.nerve_center_state_pipeline_throughput import NerveCenterStatePipelineThroughput
        from ..models.suite_status import SuiteStatus
        from ..models.threat_pulse import ThreatPulse

        d = dict(src_dict)
        threat_pulse = ThreatPulse.from_dict(d.pop("threat_pulse"))

        suites = []
        _suites = d.pop("suites")
        for suites_item_data in _suites:
            suites_item = SuiteStatus.from_dict(suites_item_data)

            suites.append(suites_item)

        intelligence_links = []
        _intelligence_links = d.pop("intelligence_links")
        for intelligence_links_item_data in _intelligence_links:
            intelligence_links_item = IntelligenceLink.from_dict(intelligence_links_item_data)

            intelligence_links.append(intelligence_links_item)

        recent_actions = []
        _recent_actions = d.pop("recent_actions")
        for recent_actions_item_data in _recent_actions:
            recent_actions_item = AutoRemediationAction.from_dict(recent_actions_item_data)

            recent_actions.append(recent_actions_item)

        pipeline_throughput = NerveCenterStatePipelineThroughput.from_dict(d.pop("pipeline_throughput"))

        decision_engine = NerveCenterStateDecisionEngine.from_dict(d.pop("decision_engine"))

        compliance_posture = NerveCenterStateCompliancePosture.from_dict(d.pop("compliance_posture"))

        nerve_center_state = cls(
            threat_pulse=threat_pulse,
            suites=suites,
            intelligence_links=intelligence_links,
            recent_actions=recent_actions,
            pipeline_throughput=pipeline_throughput,
            decision_engine=decision_engine,
            compliance_posture=compliance_posture,
        )

        nerve_center_state.additional_properties = d
        return nerve_center_state

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
