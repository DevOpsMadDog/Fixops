from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.decision_request_business_context import DecisionRequestBusinessContext
    from ..models.decision_request_sbom_data_type_0 import DecisionRequestSbomDataType0
    from ..models.decision_request_security_findings_item import DecisionRequestSecurityFindingsItem
    from ..models.decision_request_threat_model_type_0 import DecisionRequestThreatModelType0


T = TypeVar("T", bound="DecisionRequest")


@_attrs_define
class DecisionRequest:
    """
    Attributes:
        service_name (str | Unset):  Default: 'unknown-service'.
        environment (str | Unset):  Default: 'production'.
        business_context (DecisionRequestBusinessContext | Unset):
        security_findings (list[DecisionRequestSecurityFindingsItem] | Unset):
        sbom_data (DecisionRequestSbomDataType0 | None | Unset):
        threat_model (DecisionRequestThreatModelType0 | None | Unset):
    """

    service_name: str | Unset = "unknown-service"
    environment: str | Unset = "production"
    business_context: DecisionRequestBusinessContext | Unset = UNSET
    security_findings: list[DecisionRequestSecurityFindingsItem] | Unset = UNSET
    sbom_data: DecisionRequestSbomDataType0 | None | Unset = UNSET
    threat_model: DecisionRequestThreatModelType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.decision_request_sbom_data_type_0 import DecisionRequestSbomDataType0
        from ..models.decision_request_threat_model_type_0 import DecisionRequestThreatModelType0

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

        sbom_data: dict[str, Any] | None | Unset
        if isinstance(self.sbom_data, Unset):
            sbom_data = UNSET
        elif isinstance(self.sbom_data, DecisionRequestSbomDataType0):
            sbom_data = self.sbom_data.to_dict()
        else:
            sbom_data = self.sbom_data

        threat_model: dict[str, Any] | None | Unset
        if isinstance(self.threat_model, Unset):
            threat_model = UNSET
        elif isinstance(self.threat_model, DecisionRequestThreatModelType0):
            threat_model = self.threat_model.to_dict()
        else:
            threat_model = self.threat_model

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if service_name is not UNSET:
            field_dict["service_name"] = service_name
        if environment is not UNSET:
            field_dict["environment"] = environment
        if business_context is not UNSET:
            field_dict["business_context"] = business_context
        if security_findings is not UNSET:
            field_dict["security_findings"] = security_findings
        if sbom_data is not UNSET:
            field_dict["sbom_data"] = sbom_data
        if threat_model is not UNSET:
            field_dict["threat_model"] = threat_model

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.decision_request_business_context import DecisionRequestBusinessContext
        from ..models.decision_request_sbom_data_type_0 import DecisionRequestSbomDataType0
        from ..models.decision_request_security_findings_item import DecisionRequestSecurityFindingsItem
        from ..models.decision_request_threat_model_type_0 import DecisionRequestThreatModelType0

        d = dict(src_dict)
        service_name = d.pop("service_name", UNSET)

        environment = d.pop("environment", UNSET)

        _business_context = d.pop("business_context", UNSET)
        business_context: DecisionRequestBusinessContext | Unset
        if isinstance(_business_context, Unset):
            business_context = UNSET
        else:
            business_context = DecisionRequestBusinessContext.from_dict(_business_context)

        _security_findings = d.pop("security_findings", UNSET)
        security_findings: list[DecisionRequestSecurityFindingsItem] | Unset = UNSET
        if _security_findings is not UNSET:
            security_findings = []
            for security_findings_item_data in _security_findings:
                security_findings_item = DecisionRequestSecurityFindingsItem.from_dict(security_findings_item_data)

                security_findings.append(security_findings_item)

        def _parse_sbom_data(data: object) -> DecisionRequestSbomDataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                sbom_data_type_0 = DecisionRequestSbomDataType0.from_dict(data)

                return sbom_data_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DecisionRequestSbomDataType0 | None | Unset, data)

        sbom_data = _parse_sbom_data(d.pop("sbom_data", UNSET))

        def _parse_threat_model(data: object) -> DecisionRequestThreatModelType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                threat_model_type_0 = DecisionRequestThreatModelType0.from_dict(data)

                return threat_model_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DecisionRequestThreatModelType0 | None | Unset, data)

        threat_model = _parse_threat_model(d.pop("threat_model", UNSET))

        decision_request = cls(
            service_name=service_name,
            environment=environment,
            business_context=business_context,
            security_findings=security_findings,
            sbom_data=sbom_data,
            threat_model=threat_model,
        )

        decision_request.additional_properties = d
        return decision_request

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
