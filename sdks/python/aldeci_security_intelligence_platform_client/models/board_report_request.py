from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.board_report_request_compliance_data import BoardReportRequestComplianceData
    from ..models.board_report_request_kpi_values import BoardReportRequestKpiValues
    from ..models.board_report_request_previous_kpi_values_type_0 import BoardReportRequestPreviousKpiValuesType0
    from ..models.fair_scenario_request import FAIRScenarioRequest


T = TypeVar("T", bound="BoardReportRequest")


@_attrs_define
class BoardReportRequest:
    """Request body for board report generation.

    Attributes:
        org_id (str | Unset): Organisation identifier Default: 'default'.
        fair_scenarios (list[FAIRScenarioRequest] | Unset): FAIR risk scenarios to simulate
        compliance_data (BoardReportRequestComplianceData | Unset): Regulation → compliance % mapping (e.g. {"soc2":
            78.5})
        kpi_values (BoardReportRequestKpiValues | Unset): KPI ID → current value mapping
        previous_kpi_values (BoardReportRequestPreviousKpiValuesType0 | None | Unset): Prior-period KPI values for trend
            computation
        prior_quarter_risk_score (float | None | Unset): Last quarter's risk score for QoQ delta calculation
    """

    org_id: str | Unset = "default"
    fair_scenarios: list[FAIRScenarioRequest] | Unset = UNSET
    compliance_data: BoardReportRequestComplianceData | Unset = UNSET
    kpi_values: BoardReportRequestKpiValues | Unset = UNSET
    previous_kpi_values: BoardReportRequestPreviousKpiValuesType0 | None | Unset = UNSET
    prior_quarter_risk_score: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.board_report_request_previous_kpi_values_type_0 import BoardReportRequestPreviousKpiValuesType0

        org_id = self.org_id

        fair_scenarios: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.fair_scenarios, Unset):
            fair_scenarios = []
            for fair_scenarios_item_data in self.fair_scenarios:
                fair_scenarios_item = fair_scenarios_item_data.to_dict()
                fair_scenarios.append(fair_scenarios_item)

        compliance_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.compliance_data, Unset):
            compliance_data = self.compliance_data.to_dict()

        kpi_values: dict[str, Any] | Unset = UNSET
        if not isinstance(self.kpi_values, Unset):
            kpi_values = self.kpi_values.to_dict()

        previous_kpi_values: dict[str, Any] | None | Unset
        if isinstance(self.previous_kpi_values, Unset):
            previous_kpi_values = UNSET
        elif isinstance(self.previous_kpi_values, BoardReportRequestPreviousKpiValuesType0):
            previous_kpi_values = self.previous_kpi_values.to_dict()
        else:
            previous_kpi_values = self.previous_kpi_values

        prior_quarter_risk_score: float | None | Unset
        if isinstance(self.prior_quarter_risk_score, Unset):
            prior_quarter_risk_score = UNSET
        else:
            prior_quarter_risk_score = self.prior_quarter_risk_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if fair_scenarios is not UNSET:
            field_dict["fair_scenarios"] = fair_scenarios
        if compliance_data is not UNSET:
            field_dict["compliance_data"] = compliance_data
        if kpi_values is not UNSET:
            field_dict["kpi_values"] = kpi_values
        if previous_kpi_values is not UNSET:
            field_dict["previous_kpi_values"] = previous_kpi_values
        if prior_quarter_risk_score is not UNSET:
            field_dict["prior_quarter_risk_score"] = prior_quarter_risk_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.board_report_request_compliance_data import BoardReportRequestComplianceData
        from ..models.board_report_request_kpi_values import BoardReportRequestKpiValues
        from ..models.board_report_request_previous_kpi_values_type_0 import BoardReportRequestPreviousKpiValuesType0
        from ..models.fair_scenario_request import FAIRScenarioRequest

        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        _fair_scenarios = d.pop("fair_scenarios", UNSET)
        fair_scenarios: list[FAIRScenarioRequest] | Unset = UNSET
        if _fair_scenarios is not UNSET:
            fair_scenarios = []
            for fair_scenarios_item_data in _fair_scenarios:
                fair_scenarios_item = FAIRScenarioRequest.from_dict(fair_scenarios_item_data)

                fair_scenarios.append(fair_scenarios_item)

        _compliance_data = d.pop("compliance_data", UNSET)
        compliance_data: BoardReportRequestComplianceData | Unset
        if isinstance(_compliance_data, Unset):
            compliance_data = UNSET
        else:
            compliance_data = BoardReportRequestComplianceData.from_dict(_compliance_data)

        _kpi_values = d.pop("kpi_values", UNSET)
        kpi_values: BoardReportRequestKpiValues | Unset
        if isinstance(_kpi_values, Unset):
            kpi_values = UNSET
        else:
            kpi_values = BoardReportRequestKpiValues.from_dict(_kpi_values)

        def _parse_previous_kpi_values(data: object) -> BoardReportRequestPreviousKpiValuesType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                previous_kpi_values_type_0 = BoardReportRequestPreviousKpiValuesType0.from_dict(data)

                return previous_kpi_values_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(BoardReportRequestPreviousKpiValuesType0 | None | Unset, data)

        previous_kpi_values = _parse_previous_kpi_values(d.pop("previous_kpi_values", UNSET))

        def _parse_prior_quarter_risk_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        prior_quarter_risk_score = _parse_prior_quarter_risk_score(d.pop("prior_quarter_risk_score", UNSET))

        board_report_request = cls(
            org_id=org_id,
            fair_scenarios=fair_scenarios,
            compliance_data=compliance_data,
            kpi_values=kpi_values,
            previous_kpi_values=previous_kpi_values,
            prior_quarter_risk_score=prior_quarter_risk_score,
        )

        board_report_request.additional_properties = d
        return board_report_request

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
