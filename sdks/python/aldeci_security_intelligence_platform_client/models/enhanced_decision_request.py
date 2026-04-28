from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.enhanced_decision_request_ai_agent_analysis_type_0 import EnhancedDecisionRequestAiAgentAnalysisType0
    from ..models.enhanced_decision_request_business_context import EnhancedDecisionRequestBusinessContext
    from ..models.enhanced_decision_request_cnapp_type_0 import EnhancedDecisionRequestCnappType0
    from ..models.enhanced_decision_request_exploitability_type_0 import EnhancedDecisionRequestExploitabilityType0
    from ..models.enhanced_decision_request_marketplace_recommendations_type_0_item import (
        EnhancedDecisionRequestMarketplaceRecommendationsType0Item,
    )
    from ..models.enhanced_decision_request_security_findings_item import EnhancedDecisionRequestSecurityFindingsItem


T = TypeVar("T", bound="EnhancedDecisionRequest")


@_attrs_define
class EnhancedDecisionRequest:
    """
    Attributes:
        service_name (str): Primary service or application identifier
        environment (str | Unset): Deployment environment Default: 'production'.
        business_context (EnhancedDecisionRequestBusinessContext | Unset):
        security_findings (list[EnhancedDecisionRequestSecurityFindingsItem] | Unset):
        compliance_requirements (list[str] | Unset):
        cnapp (EnhancedDecisionRequestCnappType0 | None | Unset):
        exploitability (EnhancedDecisionRequestExploitabilityType0 | None | Unset):
        ai_agent_analysis (EnhancedDecisionRequestAiAgentAnalysisType0 | None | Unset):
        marketplace_recommendations (list[EnhancedDecisionRequestMarketplaceRecommendationsType0Item] | None | Unset):
    """

    service_name: str
    environment: str | Unset = "production"
    business_context: EnhancedDecisionRequestBusinessContext | Unset = UNSET
    security_findings: list[EnhancedDecisionRequestSecurityFindingsItem] | Unset = UNSET
    compliance_requirements: list[str] | Unset = UNSET
    cnapp: EnhancedDecisionRequestCnappType0 | None | Unset = UNSET
    exploitability: EnhancedDecisionRequestExploitabilityType0 | None | Unset = UNSET
    ai_agent_analysis: EnhancedDecisionRequestAiAgentAnalysisType0 | None | Unset = UNSET
    marketplace_recommendations: list[EnhancedDecisionRequestMarketplaceRecommendationsType0Item] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.enhanced_decision_request_ai_agent_analysis_type_0 import (
            EnhancedDecisionRequestAiAgentAnalysisType0,
        )
        from ..models.enhanced_decision_request_cnapp_type_0 import EnhancedDecisionRequestCnappType0
        from ..models.enhanced_decision_request_exploitability_type_0 import EnhancedDecisionRequestExploitabilityType0

        service_name = self.service_name

        environment = self.environment

        business_context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.business_context, Unset):
            business_context = self.business_context.to_dict()

        security_findings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.security_findings, Unset):
            security_findings = []
            for security_findings_item_data in self.security_findings:
                security_findings_item = security_findings_item_data.to_dict()
                security_findings.append(security_findings_item)

        compliance_requirements: list[str] | Unset = UNSET
        if not isinstance(self.compliance_requirements, Unset):
            compliance_requirements = self.compliance_requirements

        cnapp: dict[str, Any] | None | Unset
        if isinstance(self.cnapp, Unset):
            cnapp = UNSET
        elif isinstance(self.cnapp, EnhancedDecisionRequestCnappType0):
            cnapp = self.cnapp.to_dict()
        else:
            cnapp = self.cnapp

        exploitability: dict[str, Any] | None | Unset
        if isinstance(self.exploitability, Unset):
            exploitability = UNSET
        elif isinstance(self.exploitability, EnhancedDecisionRequestExploitabilityType0):
            exploitability = self.exploitability.to_dict()
        else:
            exploitability = self.exploitability

        ai_agent_analysis: dict[str, Any] | None | Unset
        if isinstance(self.ai_agent_analysis, Unset):
            ai_agent_analysis = UNSET
        elif isinstance(self.ai_agent_analysis, EnhancedDecisionRequestAiAgentAnalysisType0):
            ai_agent_analysis = self.ai_agent_analysis.to_dict()
        else:
            ai_agent_analysis = self.ai_agent_analysis

        marketplace_recommendations: list[dict[str, Any]] | None | Unset
        if isinstance(self.marketplace_recommendations, Unset):
            marketplace_recommendations = UNSET
        elif isinstance(self.marketplace_recommendations, list):
            marketplace_recommendations = []
            for marketplace_recommendations_type_0_item_data in self.marketplace_recommendations:
                marketplace_recommendations_type_0_item = marketplace_recommendations_type_0_item_data.to_dict()
                marketplace_recommendations.append(marketplace_recommendations_type_0_item)

        else:
            marketplace_recommendations = self.marketplace_recommendations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "service_name": service_name,
            }
        )
        if environment is not UNSET:
            field_dict["environment"] = environment
        if business_context is not UNSET:
            field_dict["business_context"] = business_context
        if security_findings is not UNSET:
            field_dict["security_findings"] = security_findings
        if compliance_requirements is not UNSET:
            field_dict["compliance_requirements"] = compliance_requirements
        if cnapp is not UNSET:
            field_dict["cnapp"] = cnapp
        if exploitability is not UNSET:
            field_dict["exploitability"] = exploitability
        if ai_agent_analysis is not UNSET:
            field_dict["ai_agent_analysis"] = ai_agent_analysis
        if marketplace_recommendations is not UNSET:
            field_dict["marketplace_recommendations"] = marketplace_recommendations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.enhanced_decision_request_ai_agent_analysis_type_0 import (
            EnhancedDecisionRequestAiAgentAnalysisType0,
        )
        from ..models.enhanced_decision_request_business_context import EnhancedDecisionRequestBusinessContext
        from ..models.enhanced_decision_request_cnapp_type_0 import EnhancedDecisionRequestCnappType0
        from ..models.enhanced_decision_request_exploitability_type_0 import EnhancedDecisionRequestExploitabilityType0
        from ..models.enhanced_decision_request_marketplace_recommendations_type_0_item import (
            EnhancedDecisionRequestMarketplaceRecommendationsType0Item,
        )
        from ..models.enhanced_decision_request_security_findings_item import (
            EnhancedDecisionRequestSecurityFindingsItem,
        )

        d = dict(src_dict)
        service_name = d.pop("service_name")

        environment = d.pop("environment", UNSET)

        _business_context = d.pop("business_context", UNSET)
        business_context: EnhancedDecisionRequestBusinessContext | Unset
        if isinstance(_business_context, Unset):
            business_context = UNSET
        else:
            business_context = EnhancedDecisionRequestBusinessContext.from_dict(_business_context)

        _security_findings = d.pop("security_findings", UNSET)
        security_findings: list[EnhancedDecisionRequestSecurityFindingsItem] | Unset = UNSET
        if _security_findings is not UNSET:
            security_findings = []
            for security_findings_item_data in _security_findings:
                security_findings_item = EnhancedDecisionRequestSecurityFindingsItem.from_dict(
                    security_findings_item_data
                )

                security_findings.append(security_findings_item)

        compliance_requirements = cast(list[str], d.pop("compliance_requirements", UNSET))

        def _parse_cnapp(data: object) -> EnhancedDecisionRequestCnappType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                cnapp_type_0 = EnhancedDecisionRequestCnappType0.from_dict(data)

                return cnapp_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EnhancedDecisionRequestCnappType0 | None | Unset, data)

        cnapp = _parse_cnapp(d.pop("cnapp", UNSET))

        def _parse_exploitability(data: object) -> EnhancedDecisionRequestExploitabilityType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                exploitability_type_0 = EnhancedDecisionRequestExploitabilityType0.from_dict(data)

                return exploitability_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EnhancedDecisionRequestExploitabilityType0 | None | Unset, data)

        exploitability = _parse_exploitability(d.pop("exploitability", UNSET))

        def _parse_ai_agent_analysis(data: object) -> EnhancedDecisionRequestAiAgentAnalysisType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                ai_agent_analysis_type_0 = EnhancedDecisionRequestAiAgentAnalysisType0.from_dict(data)

                return ai_agent_analysis_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(EnhancedDecisionRequestAiAgentAnalysisType0 | None | Unset, data)

        ai_agent_analysis = _parse_ai_agent_analysis(d.pop("ai_agent_analysis", UNSET))

        def _parse_marketplace_recommendations(
            data: object,
        ) -> list[EnhancedDecisionRequestMarketplaceRecommendationsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                marketplace_recommendations_type_0 = []
                _marketplace_recommendations_type_0 = data
                for marketplace_recommendations_type_0_item_data in _marketplace_recommendations_type_0:
                    marketplace_recommendations_type_0_item = (
                        EnhancedDecisionRequestMarketplaceRecommendationsType0Item.from_dict(
                            marketplace_recommendations_type_0_item_data
                        )
                    )

                    marketplace_recommendations_type_0.append(marketplace_recommendations_type_0_item)

                return marketplace_recommendations_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[EnhancedDecisionRequestMarketplaceRecommendationsType0Item] | None | Unset, data)

        marketplace_recommendations = _parse_marketplace_recommendations(d.pop("marketplace_recommendations", UNSET))

        enhanced_decision_request = cls(
            service_name=service_name,
            environment=environment,
            business_context=business_context,
            security_findings=security_findings,
            compliance_requirements=compliance_requirements,
            cnapp=cnapp,
            exploitability=exploitability,
            ai_agent_analysis=ai_agent_analysis,
            marketplace_recommendations=marketplace_recommendations,
        )

        enhanced_decision_request.additional_properties = d
        return enhanced_decision_request

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
